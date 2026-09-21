"""Real-discovery tests for plugin-provided browser login backends."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

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
        display_name=display_name,
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
) -> None:
    entries = {
        plugin_id: {"granted_capabilities": capabilities}
        for plugin_id, capabilities in (grants or {}).items()
    }
    (home / "config.yaml").write_text(
        yaml.safe_dump({"plugins": {"enabled": plugin_ids, "entries": entries}}),
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
