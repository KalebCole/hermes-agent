"""Real-discovery tests for plugin-provided browser login backends."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from agent.vault_backends import backend_for_handle, enabled_backends
from agent.vault_backends import registry as login_backend_registry
from hermes_cli.plugins import PluginManager


_BACKEND_CLASS = """
from agent.vault_backends.base import LoginBackend

class {class_name}(LoginBackend):
    name = {name!r}
    display_name = {display_name!r}
    prefix = {prefix!r}
    needs_unlock = {needs_unlock!r}

    def __init__(self, config):
        self.config = config

    def list_items(self):
        return []

    def get_meta(self, handle):
        return None

    def resolve_password(self, handle):
        return ""
"""


@pytest.fixture(autouse=True)
def _clean_login_backend_registry():
    login_backend_registry._reset_for_tests()
    yield
    login_backend_registry._reset_for_tests()


def _write_plugin(
    home: Path,
    plugin_id: str,
    *,
    backend_name: str,
    display_name: str,
    prefix: str,
    needs_unlock: bool = False,
    replace_stock: bool = False,
    class_name: str = "BrokerBackend",
    class_display_name: str | None = None,
) -> None:
    plugin_dir = home / "plugins" / plugin_id
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text(
        yaml.safe_dump(
            {
                "name": plugin_id,
                "version": "0.1.0",
                "description": f"Test plugin {plugin_id}",
            }
        ),
        encoding="utf-8",
    )
    source = _BACKEND_CLASS.format(
        class_name=class_name,
        name=backend_name,
        display_name=class_display_name or display_name,
        prefix=prefix,
        needs_unlock=needs_unlock,
    )
    source += f"""

def register(ctx):
    ctx.register_login_backend(
        {class_name},
        name={backend_name!r},
        display_name={display_name!r},
        prefix={prefix!r},
        needs_unlock={needs_unlock!r},
        replace_stock={replace_stock!r},
    )
"""
    (plugin_dir / "__init__.py").write_text(source, encoding="utf-8")


def _configure_plugins(
    home: Path,
    plugin_ids: list[str],
    *,
    grants: dict[str, list[str]] | None = None,
    vault: dict | None = None,
) -> None:
    entries = {
        plugin_id: {"granted_capabilities": capabilities}
        for plugin_id, capabilities in (grants or {}).items()
    }
    (home / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "plugins": {"enabled": plugin_ids, "entries": entries},
                **({"vault": vault} if vault is not None else {}),
            }
        ),
        encoding="utf-8",
    )


def test_real_discovery_registers_login_backend_in_manager_scope():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="broker",
        display_name="Broker vault",
        prefix="broker:",
        needs_unlock=True,
    )
    _configure_plugins(home, ["broker-plugin"])

    manager = PluginManager()
    manager.discover_and_load()

    provider = login_backend_registry.snapshot_registration(
        "broker", scope=manager.scope_key
    )
    assert manager._plugins["broker-plugin"].enabled is True
    assert provider is not None
    assert provider.prefix == "broker:"
    assert provider.needs_unlock is True
    assert provider.create({}).name == "broker"


def test_real_discovery_routes_login_backend_with_its_own_config_and_reloads_once():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="broker",
        display_name="Broker vault",
        prefix="broker:",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        vault={
            "broker": {"endpoint": "https://broker.invalid"},
            "unrelated": {"secret": "must-not-reach-factory"},
        },
    )

    manager = PluginManager()
    manager.discover_and_load()

    with patch("agent.vault_backends.base.is_installed", return_value=False):
        backends = {backend.name: backend for backend in enabled_backends()}
        assert set(backends) == {"local", "broker"}
        assert backends["broker"].prefix == "broker:"
        assert backends["broker"].display_name == "Broker vault"
        assert backends["broker"].needs_unlock is False
        assert dict(backends["broker"].config) == {
            "endpoint": "https://broker.invalid"
        }
        routed = backend_for_handle("broker:item-1")
        assert routed is not None
        assert routed.name == "broker"

        manager.unload("broker-plugin")
        assert "broker" not in {backend.name for backend in enabled_backends()}

        manager.discover_and_load(force=True)
        assert [backend.name for backend in enabled_backends()].count("broker") == 1


def test_login_backend_discovery_is_isolated_across_profiles_and_unload():
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    root = Path(os.environ["HERMES_HOME"]).parent
    home_a = root / "profile-a"
    home_b = root / "profile-b"
    _write_plugin(
        home_a,
        "alpha-plugin",
        backend_name="alpha",
        display_name="Alpha vault",
        prefix="alpha:",
    )
    _configure_plugins(home_a, ["alpha-plugin"])
    _write_plugin(
        home_b,
        "beta-plugin",
        backend_name="beta",
        display_name="Beta vault",
        prefix="beta:",
    )
    _configure_plugins(home_b, ["beta-plugin"])

    with patch("agent.vault_backends.base.is_installed", return_value=False):
        token_a = set_hermes_home_override(home_a)
        try:
            manager_a = PluginManager()
            manager_a.discover_and_load()
            assert [backend.name for backend in enabled_backends()] == ["local", "alpha"]
        finally:
            reset_hermes_home_override(token_a)

        token_b = set_hermes_home_override(home_b)
        try:
            manager_b = PluginManager()
            manager_b.discover_and_load()
            assert [backend.name for backend in enabled_backends()] == ["local", "beta"]
            manager_a.unload("alpha-plugin")
            assert [backend.name for backend in enabled_backends()] == ["local", "beta"]
        finally:
            reset_hermes_home_override(token_b)

        token_a = set_hermes_home_override(home_a)
        try:
            assert [backend.name for backend in enabled_backends()] == ["local"]
        finally:
            reset_hermes_home_override(token_a)


def test_login_backend_provider_metadata_drives_cli_and_tui_sources(monkeypatch):
    import tui_gateway.server as server
    from hermes_cli import vault as vault_cli

    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="broker",
        display_name="Broker vault",
        prefix="broker:",
    )
    _configure_plugins(home, ["broker-plugin"])
    manager = PluginManager()
    manager.discover_and_load()
    monkeypatch.setattr("agent.vault_backends.base.is_installed", lambda name: False)

    result = server._methods["vault.sources"](1, {})["result"]["sources"]
    broker = next(row for row in result if row["name"] == "broker")
    assert broker == {
        "name": "broker",
        "display_name": "Broker vault",
        "enabled": True,
        "needs_unlock": False,
        "unlocked": True,
        "installed": True,
    }

    lines: list[str] = []
    monkeypatch.setattr(
        vault_cli,
        "_console",
        lambda: SimpleNamespace(print=lambda value: lines.append(str(value))),
    )
    vault_cli._cmd_sources(SimpleNamespace(enable=None, disable=None))
    assert any("Broker vault" in line and "detected" in line for line in lines)

    server._methods["vault.source.set"](
        2, {"name": "broker", "enabled": False}
    )
    assert "broker" not in {backend.name for backend in enabled_backends()}


def test_login_backend_factory_metadata_must_match_registration():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="broker",
        display_name="Broker vault",
        class_display_name="Wrong broker",
        prefix="broker:",
    )
    _configure_plugins(home, ["broker-plugin"])
    manager = PluginManager()
    manager.discover_and_load()

    with patch("agent.vault_backends.base.is_installed", return_value=False):
        with pytest.raises(ValueError, match="inconsistent public metadata"):
            enabled_backends()


def test_real_discovery_rejects_duplicate_backend_name():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "a-broker-plugin",
        backend_name="broker",
        display_name="Broker vault",
        prefix="broker:",
    )
    _write_plugin(
        home,
        "b-name-plugin",
        backend_name="broker",
        display_name="Other broker",
        prefix="other:",
    )
    _configure_plugins(home, ["a-broker-plugin", "b-name-plugin"])

    manager = PluginManager()
    manager.discover_and_load()

    second_plugin = manager._plugins["b-name-plugin"]
    assert second_plugin.enabled is False
    assert "backend name 'broker' is already registered" in second_plugin.error


def test_real_discovery_rejects_duplicate_handle_prefix():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "a-broker-plugin",
        backend_name="broker",
        display_name="Broker vault",
        prefix="broker:",
    )
    _write_plugin(
        home,
        "b-prefix-plugin",
        backend_name="other",
        display_name="Other vault",
        prefix="broker:",
    )
    _configure_plugins(home, ["a-broker-plugin", "b-prefix-plugin"])

    manager = PluginManager()
    manager.discover_and_load()

    prefix_plugin = manager._plugins["b-prefix-plugin"]
    assert prefix_plugin.enabled is False
    assert "handle prefix 'broker:' is already registered" in prefix_plugin.error


@pytest.mark.parametrize("prefix", ["vault_plugin:", "op:team:", "bw:team:"])
def test_real_discovery_rejects_stock_handle_prefix_extensions(prefix: str):
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "overlap-plugin",
        backend_name="overlap",
        display_name="Overlapping vault",
        prefix=prefix,
    )
    _configure_plugins(home, ["overlap-plugin"])

    manager = PluginManager()
    manager.discover_and_load()

    plugin = manager._plugins["overlap-plugin"]
    assert plugin.enabled is False
    assert f"handle prefix {prefix!r} overlaps reserved stock prefix" in plugin.error


@pytest.mark.parametrize(
    ("first_prefix", "second_prefix"),
    [
        ("broker:", "broker:special:"),
        ("broker:special:", "broker:"),
    ],
)
def test_real_discovery_rejects_overlapping_plugin_handle_prefixes(
    first_prefix: str,
    second_prefix: str,
):
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "a-first-plugin",
        backend_name="first",
        display_name="First vault",
        prefix=first_prefix,
    )
    _write_plugin(
        home,
        "b-second-plugin",
        backend_name="second",
        display_name="Second vault",
        prefix=second_prefix,
    )
    _configure_plugins(home, ["a-first-plugin", "b-second-plugin"])

    manager = PluginManager()
    manager.discover_and_load()

    second_plugin = manager._plugins["b-second-plugin"]
    assert second_plugin.enabled is False
    assert (
        f"handle prefix {second_prefix!r} overlaps registered prefix "
        f"{first_prefix!r}"
    ) in second_plugin.error


def test_stock_replacement_requires_capability_grant():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-bitwarden",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        needs_unlock=True,
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(home, ["broker-bitwarden"])

    manager = PluginManager()
    manager.discover_and_load()

    plugin = manager._plugins["broker-bitwarden"]
    assert plugin.enabled is False
    assert "vault.login_backend_replace" in plugin.error
    assert "granted_capabilities" in plugin.error
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ) is None


def test_granted_capability_allows_exact_stock_replacement():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-bitwarden",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        needs_unlock=True,
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-bitwarden"],
        grants={"broker-bitwarden": ["vault.login_backend_replace"]},
    )

    manager = PluginManager()
    manager.discover_and_load()

    provider = login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    )
    assert manager._plugins["broker-bitwarden"].enabled is True
    assert provider is not None
    assert provider.replaces_stock is True
    assert provider.prefix == "bw:"


def test_login_backend_stock_replacement_occupies_stock_slot_without_changing_tools():
    from tools import browser_vault_tool  # noqa: F401
    from tools.registry import registry as tool_registry

    home = Path(os.environ["HERMES_HOME"])
    tool_names = (
        "browser_vault_list",
        "browser_vault_fill",
        "browser_vault_save_login",
        "browser_vault_enter_code",
    )
    registrations_before = {
        name: tool_registry.get_entry(name) for name in tool_names
    }
    _write_plugin(
        home,
        "broker-bitwarden",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        needs_unlock=True,
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-bitwarden"],
        grants={"broker-bitwarden": ["vault.login_backend_replace"]},
    )

    manager = PluginManager()
    manager.discover_and_load()

    with patch("agent.vault_backends.base.is_installed", return_value=True):
        backends = enabled_backends()
        assert [backend.name for backend in backends] == [
            "local",
            "onepassword",
            "bitwarden",
        ]
        replacements = [
            backend for backend in backends if backend.name == "bitwarden"
        ]
        assert len(replacements) == 1
        assert replacements[0].display_name == "Broker Bitwarden"
        routed = backend_for_handle("bw:item")
        assert routed is not None
        assert routed.display_name == "Broker Bitwarden"

    assert {
        name: tool_registry.get_entry(name) for name in tool_names
    } == registrations_before


@pytest.mark.parametrize(
    ("backend_name", "prefix", "message"),
    [
        ("local", "vault_", "cannot replace stock backend 'local'"),
        ("broker", "broker:", "cannot replace non-stock backend 'broker'"),
        (
            "bitwarden",
            "not-bw:",
            "stock backend 'bitwarden' requires handle prefix 'bw:'",
        ),
    ],
)
def test_stock_replacement_rejects_invalid_targets(
    backend_name: str,
    prefix: str,
    message: str,
):
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "invalid-replacement",
        backend_name=backend_name,
        display_name="Invalid replacement",
        prefix=prefix,
        replace_stock=True,
    )
    _configure_plugins(
        home,
        ["invalid-replacement"],
        grants={"invalid-replacement": ["vault.login_backend_replace"]},
    )

    manager = PluginManager()
    manager.discover_and_load()

    plugin = manager._plugins["invalid-replacement"]
    assert plugin.enabled is False
    assert message in plugin.error


@pytest.mark.parametrize(
    ("backend_name", "prefix", "message"),
    [
        ("onepassword", "broker:", "stock backend name 'onepassword' is reserved"),
        ("broker", "op:", "stock handle prefix 'op:' is reserved"),
        ("local", "broker:", "stock backend name 'local' is reserved"),
        ("broker", "vault_", "stock handle prefix 'vault_' is reserved"),
    ],
)
def test_ordinary_registration_cannot_claim_stock_names_or_prefixes(
    backend_name: str,
    prefix: str,
    message: str,
):
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "stock-claim",
        backend_name=backend_name,
        display_name="Stock claim",
        prefix=prefix,
    )
    _configure_plugins(home, ["stock-claim"])

    manager = PluginManager()
    manager.discover_and_load()

    plugin = manager._plugins["stock-claim"]
    assert plugin.enabled is False
    assert message in plugin.error
