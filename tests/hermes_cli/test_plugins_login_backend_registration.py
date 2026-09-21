"""Real-discovery tests for plugin-provided browser login backends."""

from __future__ import annotations

import os
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from agent.vault_backends import (
    available_backend_providers,
    backend_for_handle,
    enabled_backends,
)
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


def _write_noninteractive_plugin(home: Path, *, rejection: str = "") -> None:
    plugin_dir = home / "plugins" / "broker-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text(
        "name: broker-plugin\nversion: 0.1.0\n", encoding="utf-8"
    )
    (plugin_dir / "__init__.py").write_text(
        f"""
from agent.vault_backends.base import LoginBackend, UnlockRequired
from agent.vault_store import VaultItemMeta

session_valid = {bool(rejection)!r}
unlock_calls = 0
rejection = {rejection!r}
rejected = False

class BrokerBackend(LoginBackend):
    name = "broker"
    display_name = "Broker vault"
    prefix = "broker:"
    needs_unlock = True

    def __init__(self, config):
        self.config = config

    def is_unlocked(self):
        return session_valid

    def unlock_noninteractive(self):
        global session_valid, unlock_calls
        session_valid = True
        unlock_calls += 1
        return True

    def list_items(self):
        if not session_valid:
            return []
        return [self._meta()]

    def get_meta(self, handle):
        global rejected
        if rejection == "get_meta" and not rejected:
            rejected = True
            raise UnlockRequired(self)
        return self._meta() if handle == "broker:item" else None

    def resolve_password(self, handle):
        global rejected
        if rejection == "resolve_password" and not rejected:
            rejected = True
            raise UnlockRequired(self)
        return "plugin-secret"

    @staticmethod
    def _meta():
        return VaultItemMeta(
            id="broker:item",
            kind="login",
            label="Broker login",
            origin="https://example.com",
            created_at="2026-09-21T00:00:00Z",
            identifier_type="email",
            identifier="user@example.com",
            allowed_origins=("https://example.com",),
        )

def register(ctx):
    ctx.register_login_backend(
        BrokerBackend,
        name="broker",
        display_name="Broker vault",
        prefix="broker:",
        needs_unlock=True,
    )
""",
        encoding="utf-8",
    )


def _discover_noninteractive_plugin(home: Path, *, rejection: str = ""):
    _write_noninteractive_plugin(home, rejection=rejection)
    _configure_plugins(home, ["broker-plugin"])
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    assert module is not None
    return module


def test_noninteractive_list_refreshes_plugin_backend_without_prompt():
    from tools.browser_vault_tool import browser_vault_list

    home = Path(os.environ["HERMES_HOME"])
    module = _discover_noninteractive_plugin(home)

    with patch("agent.vault_backends.base.is_installed", return_value=False), patch(
        "agent.vault_backends.unlock.can_prompt_here", return_value=False
    ):
        result = json.loads(browser_vault_list())

    assert result["items"] == [
        {
            "handle": "broker:item",
            "backend": "broker",
            "label": "Broker login",
            "kind": "login",
            "origin": "https://example.com",
            "available": True,
            "two_factor": (
                "automatic if the manager stores a TOTP seed, else the user is asked"
            ),
            "identifier": "user@example.com",
            "identifier_type": "email",
        }
    ]
    assert "locked" not in result
    assert module.unlock_calls == 1


def test_noninteractive_unlock_succeeds_in_headless_session_without_secret():
    from tools.browser_vault_tool import browser_vault_unlock

    home = Path(os.environ["HERMES_HOME"])
    module = _discover_noninteractive_plugin(home)

    with patch("agent.vault_backends.base.is_installed", return_value=False), patch(
        "agent.vault_backends.unlock.can_prompt_here", return_value=False
    ):
        result = json.loads(browser_vault_unlock("broker"))

    assert result == {"success": True, "backend": "broker"}
    assert module.unlock_calls == 1


@pytest.mark.parametrize("rejection", ["get_meta", "resolve_password"])
def test_noninteractive_fill_refreshes_rejected_session_once(rejection: str):
    from tools import browser_vault_tool

    home = Path(os.environ["HERMES_HOME"])
    module = _discover_noninteractive_plugin(home, rejection=rejection)
    controls = [
        {
            "autocomplete": "current-password",
            "formIndex": 0,
            "index": 0,
            "label": "",
            "name": "password",
            "type": "password",
        }
    ]

    with patch("agent.vault_backends.base.is_installed", return_value=False), patch.object(
        browser_vault_tool,
        "_focus_bound_origin",
        return_value="https://example.com",
    ), patch.object(
        browser_vault_tool,
        "_eval_js",
        return_value={"success": True, "result": json.dumps(controls)},
    ), patch.object(
        browser_vault_tool,
        "_eval_js_secret",
        return_value={"success": True, "result": json.dumps({"filled": 1})},
    ):
        raw = browser_vault_tool.browser_vault_fill("broker:item")

    result = json.loads(raw)
    assert result["success"] is True
    assert result["backend"] == "broker"
    assert module.unlock_calls == 1
    assert "plugin-secret" not in raw


def test_noninteractive_default_preserves_stock_bitwarden_interactive_unlock():
    from agent.vault_backends.bitwarden import BitwardenLoginBackend

    backend = BitwardenLoginBackend({})

    assert backend.unlock_noninteractive() is False


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
    global plugin_context
    plugin_context = ctx
    ctx.register_login_backend(
        {class_name},
        name={backend_name!r},
        display_name={display_name!r},
        prefix={prefix!r},
        needs_unlock={needs_unlock!r},
        replace_stock={replace_stock!r},
    )

def set_active(name, active):
    plugin_context.set_login_backend_active(name, active)
"""
    (plugin_dir / "__init__.py").write_text(source, encoding="utf-8")


def _write_dual_replacement_plugin(home: Path, plugin_id: str = "dual-broker") -> None:
    plugin_dir = home / "plugins" / plugin_id
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text(
        yaml.safe_dump(
            {
                "name": plugin_id,
                "version": "0.1.0",
                "description": "Dual stock login backend replacement",
            }
        ),
        encoding="utf-8",
    )
    source = _BACKEND_CLASS.format(
        class_name="BrokerOnePasswordBackend",
        name="onepassword",
        display_name="Broker 1Password",
        prefix="op:",
        needs_unlock=True,
    )
    source += _BACKEND_CLASS.format(
        class_name="BrokerBitwardenBackend",
        name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        needs_unlock=True,
    )
    source += """

def register(ctx):
    global plugin_context
    plugin_context = ctx
    ctx.register_login_backend(
        BrokerOnePasswordBackend,
        name="onepassword",
        display_name="Broker 1Password",
        prefix="op:",
        needs_unlock=True,
        replace_stock=True,
    )
    ctx.register_login_backend(
        BrokerBitwardenBackend,
        name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        needs_unlock=True,
        replace_stock=True,
    )

def set_active(name, active):
    plugin_context.set_login_backend_active(name, active)
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


@pytest.mark.parametrize("prior_stock", [True, False])
def test_replacement_activation_restores_prior_stock_value(prior_stock: bool):
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        needs_unlock=True,
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
        vault={
            "bitwarden": {
                "enabled": prior_stock,
                "endpoint": "https://vault.invalid",
            }
        },
    )
    path = home / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["plugins"]["entries"]["broker-plugin"]["settings"] = {"unrelated": "keep"}
    raw["display"] = {"skin": "slate"}
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module

    module.set_active("bitwarden", True)
    active = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert active["plugins"]["entries"]["broker-plugin"]["settings"] == {
        "login_backends": {
            "bitwarden": {
                "enabled": True,
                "prior_stock": {"present": True, "value": prior_stock},
            }
        },
        "unrelated": "keep",
    }
    assert active["vault"]["bitwarden"] == {
        "enabled": False,
        "endpoint": "https://vault.invalid",
    }
    assert active["display"] == {"skin": "slate"}

    module.set_active("bitwarden", False)
    inactive = yaml.safe_load(path.read_text(encoding="utf-8"))
    state = inactive["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]
    assert state["enabled"] is False
    assert inactive["vault"]["bitwarden"]["enabled"] is prior_stock
    assert "prior_stock" not in state
    assert inactive["display"] == {"skin": "slate"}


def test_replacement_activation_restores_prior_stock_absence():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
        vault={"bitwarden": {"endpoint": "https://vault.invalid"}},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"

    module.set_active("bitwarden", True)
    active = yaml.safe_load(path.read_text(encoding="utf-8"))
    state = active["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]
    assert state["prior_stock"] == {"present": False}
    assert active["vault"]["bitwarden"]["enabled"] is False

    module.set_active("bitwarden", False)
    inactive = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "enabled" not in inactive["vault"]["bitwarden"]
    state = inactive["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]
    assert "prior_stock" not in state
    assert inactive["vault"]["bitwarden"]["endpoint"] == "https://vault.invalid"


def test_repeated_replacement_activation_does_not_replace_snapshot_or_write():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
        vault={"bitwarden": {"enabled": True}},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"

    module.set_active("bitwarden", True)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["vault"]["bitwarden"]["enabled"] = "later-user-value"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = path.read_bytes()

    module.set_active("bitwarden", True)

    assert path.read_bytes() == before
    unchanged = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert unchanged["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]["prior_stock"] == {"present": True, "value": True}


@pytest.mark.parametrize(
    "prior_stock",
    [
        pytest.param(None, id="absent"),
        pytest.param({"present": True}, id="invalid"),
    ],
)
def test_repeated_replacement_activation_requires_valid_snapshot_without_writing(
    prior_stock: object,
):
    from hermes_cli import config as config_mod

    module, config_path = _replacement_activation_subject()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    state = raw["plugins"]["entries"]["broker-plugin"].setdefault(
        "settings", {}
    ).setdefault("login_backends", {}).setdefault("bitwarden", {})
    state["enabled"] = True
    if prior_stock is not None:
        state["prior_stock"] = prior_stock
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with patch.object(config_mod, "save_config") as save_config, pytest.raises(
        (TypeError, ValueError), match="login_backends.bitwarden.prior_stock"
    ):
        module.set_active("bitwarden", True)

    save_config.assert_not_called()
    assert config_path.read_bytes() == before


def test_repeated_replacement_deactivation_does_not_overwrite_later_user_change():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
        vault={"bitwarden": {"enabled": True}},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"

    module.set_active("bitwarden", True)
    module.set_active("bitwarden", False)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["vault"]["bitwarden"]["enabled"] = "later-user-value"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = path.read_bytes()

    module.set_active("bitwarden", False)

    assert path.read_bytes() == before


def test_replacement_deactivation_without_snapshot_does_not_touch_stock_key():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
        vault={"bitwarden": {"enabled": "user-value"}},
    )
    path = home / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["plugins"]["entries"]["broker-plugin"]["settings"] = {
        "login_backends": {"bitwarden": {"enabled": True}}
    }
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module

    module.set_active("bitwarden", False)

    inactive = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert inactive["vault"]["bitwarden"]["enabled"] == "user-value"
    assert inactive["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]["enabled"] is False


def test_replacement_selection_requires_explicit_owner_activation():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module

    with patch("agent.vault_backends.base.is_installed", return_value=True):
        inactive = next(
            backend for backend in enabled_backends() if backend.name == "bitwarden"
        )
        assert inactive.display_name == "Bitwarden"

        module.set_active("bitwarden", True)
        active = next(
            backend for backend in enabled_backends() if backend.name == "bitwarden"
        )
        assert active.display_name == "Broker Bitwarden"


def test_dual_replacement_activation_is_per_backend():
    home = Path(os.environ["HERMES_HOME"])
    _write_dual_replacement_plugin(home)
    _configure_plugins(
        home,
        ["dual-broker"],
        grants={"dual-broker": ["vault.login_backend_replace"]},
        vault={
            "onepassword": {"enabled": "onepassword-user-value"},
            "bitwarden": {"enabled": True},
        },
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["dual-broker"].module

    module.set_active("bitwarden", True)

    providers = {
        provider.name: provider for provider in available_backend_providers()
    }
    assert providers["onepassword"].display_name == "1Password"
    assert providers["bitwarden"].display_name == "Broker Bitwarden"
    raw = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert raw["plugins"]["entries"]["dual-broker"]["settings"] == {
        "login_backends": {
            "bitwarden": {
                "enabled": True,
                "prior_stock": {"present": True, "value": True},
            }
        }
    }
    assert raw["vault"]["onepassword"]["enabled"] == "onepassword-user-value"

    module.set_active("bitwarden", False)

    restored = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    assert restored["plugins"]["entries"]["dual-broker"]["settings"] == {
        "login_backends": {"bitwarden": {"enabled": False}}
    }
    assert restored["vault"]["onepassword"]["enabled"] == "onepassword-user-value"
    assert restored["vault"]["bitwarden"]["enabled"] is True


def _active_dual_replacement_manager(home: Path) -> tuple[PluginManager, object, Path]:
    _write_dual_replacement_plugin(home)
    _configure_plugins(
        home,
        ["dual-broker"],
        grants={"dual-broker": ["vault.login_backend_replace"]},
        vault={
            "onepassword": {"enabled": "onepassword-user-value"},
            "bitwarden": {"enabled": "bitwarden-user-value"},
        },
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["dual-broker"].module
    module.set_active("bitwarden", True)
    return manager, module, home / "config.yaml"


def _assert_bitwarden_replacement_cleaned(config_path: Path) -> None:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    state = raw["plugins"]["entries"]["dual-broker"]["settings"][
        "login_backends"
    ]["bitwarden"]
    assert state == {"enabled": False}
    assert raw["vault"]["bitwarden"]["enabled"] == "bitwarden-user-value"
    assert raw["vault"]["onepassword"]["enabled"] == "onepassword-user-value"


def test_targeted_unload_restores_active_replacement_and_consumes_snapshot():
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )

    assert manager.unload("dual-broker") is True

    _assert_bitwarden_replacement_cleaned(config_path)
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ) is None


def test_routine_unload_all_does_not_mutate_active_replacement_config():
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )
    before = config_path.read_bytes()

    assert manager.unload() is True

    assert config_path.read_bytes() == before


@pytest.mark.parametrize("force", [False, True])
def test_targeted_or_force_unload_aborts_before_disposal_on_unreadable_state(
    force: bool,
):
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )
    broken = "plugins:\n  entries: [unterminated\n"
    config_path.write_text(broken, encoding="utf-8")

    with pytest.raises(Exception, match="while parsing|expected"):
        if force:
            manager.discover_and_load(force=True)
        else:
            manager.unload("dual-broker")

    assert config_path.read_text(encoding="utf-8") == broken
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ) is not None


@pytest.mark.parametrize("force", [False, True])
def test_targeted_or_force_unload_aborts_before_disposal_on_malformed_state(
    force: bool,
):
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["entries"]["dual-broker"]["settings"]["login_backends"][
        "bitwarden"
    ]["prior_stock"] = {"present": True}
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with pytest.raises(ValueError, match="prior_stock"):
        if force:
            manager.discover_and_load(force=True)
        else:
            manager.unload("dual-broker")

    assert config_path.read_bytes() == before
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ) is not None


@pytest.mark.parametrize("action", ["targeted", "force"])
@pytest.mark.parametrize(
    "container_path",
    [
        ("plugins",),
        ("plugins", "entries"),
        ("plugins", "entries", "dual-broker"),
        ("plugins", "entries", "dual-broker", "settings"),
        (
            "plugins",
            "entries",
            "dual-broker",
            "settings",
            "login_backends",
        ),
        (
            "plugins",
            "entries",
            "dual-broker",
            "settings",
            "login_backends",
            "bitwarden",
        ),
    ],
    ids=[
        "plugins",
        "entries",
        "plugin-entry",
        "settings",
        "login-backends",
        "backend-state",
    ],
)
def test_targeted_and_force_unload_validate_replacement_parent_mappings(
    action: str,
    container_path: tuple[str, ...],
):
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    parent = raw
    for key in container_path[:-1]:
        parent = parent[key]
    parent[container_path[-1]] = []
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with pytest.raises(TypeError, match="activation path"):
        if action == "force":
            manager.discover_and_load(force=True)
        else:
            manager.unload("dual-broker")

    assert config_path.read_bytes() == before
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ) is not None


def test_routine_unload_all_does_not_read_activation_config():
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )
    broken = "plugins:\n  entries: [unterminated\n"
    config_path.write_text(broken, encoding="utf-8")

    assert manager.unload() is True

    assert config_path.read_text(encoding="utf-8") == broken
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ) is None


def test_force_reload_omitting_active_replacement_restores_stock():
    home = Path(os.environ["HERMES_HOME"])
    manager, _, config_path = _active_dual_replacement_manager(home)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["enabled"] = []
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    manager.discover_and_load(force=True)

    _assert_bitwarden_replacement_cleaned(config_path)


def test_force_reload_omitting_owner_rejects_managed_install_without_mutation():
    from hermes_cli import config as config_mod

    home = Path(os.environ["HERMES_HOME"])
    manager, _, config_path = _active_dual_replacement_manager(home)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["enabled"] = []
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()
    provider_before = login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    )

    with patch.object(config_mod, "is_managed", return_value=True), pytest.raises(
        PermissionError, match="managed install"
    ):
        manager.discover_and_load(force=True)

    assert config_path.read_bytes() == before
    assert (
        login_backend_registry.snapshot_registration(
            "bitwarden", scope=manager.scope_key
        )
        is provider_before
    )


@pytest.mark.parametrize(
    "managed_path",
    [
        "plugins.entries.dual-broker.settings.login_backends.bitwarden.enabled",
        "plugins.entries.dual-broker.settings.login_backends.bitwarden.prior_stock",
        "vault.bitwarden.enabled",
    ],
)
def test_force_reload_omitting_owner_rejects_managed_paths_without_mutation(
    managed_path: str,
):
    from hermes_cli import managed_scope

    home = Path(os.environ["HERMES_HOME"])
    manager, _, config_path = _active_dual_replacement_manager(home)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["enabled"] = []
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()
    provider_before = login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    )

    with patch.object(
        managed_scope, "is_key_managed", side_effect=lambda key: key == managed_path
    ), pytest.raises(PermissionError, match="administrator-managed"):
        manager.discover_and_load(force=True)

    assert config_path.read_bytes() == before
    assert (
        login_backend_registry.snapshot_registration(
            "bitwarden", scope=manager.scope_key
        )
        is provider_before
    )


def test_failed_force_reload_restores_stock_and_consumes_snapshot():
    home = Path(os.environ["HERMES_HOME"])
    manager, _, config_path = _active_dual_replacement_manager(home)
    (home / "plugins" / "dual-broker" / "__init__.py").write_text(
        "raise RuntimeError('reload failed')\n",
        encoding="utf-8",
    )

    manager.discover_and_load(force=True)

    _assert_bitwarden_replacement_cleaned(config_path)
    assert manager._plugins["dual-broker"].enabled is False


def test_force_reload_discovery_exception_restores_stock_and_consumes_snapshot(
    monkeypatch,
):
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )

    def raise_during_discovery():
        raise RuntimeError("discovery failed")

    monkeypatch.setattr(manager, "_discover_and_load_inner", raise_during_discovery)

    with pytest.raises(RuntimeError, match="discovery failed"):
        manager.discover_and_load(force=True)

    _assert_bitwarden_replacement_cleaned(config_path)


def test_successful_force_reload_preserves_active_replacement_snapshot():
    home = Path(os.environ["HERMES_HOME"])
    manager, _, config_path = _active_dual_replacement_manager(home)
    before = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    manager.discover_and_load(force=True)

    assert yaml.safe_load(config_path.read_text(encoding="utf-8")) == before
    providers = {
        provider.name: provider for provider in available_backend_providers()
    }
    assert providers["bitwarden"].display_name == "Broker Bitwarden"


def _prepare_different_owner_handoff(home: Path) -> tuple[PluginManager, Path]:
    _write_plugin(
        home,
        "owner-a",
        backend_name="bitwarden",
        display_name="Owner A Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="OwnerABitwardenBackend",
    )
    _write_plugin(
        home,
        "owner-b",
        backend_name="bitwarden",
        display_name="Owner B Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="OwnerBBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["owner-a"],
        grants={
            "owner-a": ["vault.login_backend_replace"],
            "owner-b": ["vault.login_backend_replace"],
        },
        vault={"bitwarden": {"enabled": "original-stock"}},
    )
    manager = PluginManager()
    manager.discover_and_load()
    manager._plugins["owner-a"].module.set_active("bitwarden", True)
    config_path = home / "config.yaml"
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["enabled"] = ["owner-b"]
    raw["plugins"]["entries"]["owner-b"]["settings"] = {
        "login_backends": {
            "bitwarden": {
                "enabled": True,
                "prior_stock": {"present": True, "value": False},
            }
        }
    }
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return manager, config_path


def test_force_reload_hands_original_snapshot_to_different_active_owner():
    manager, config_path = _prepare_different_owner_handoff(
        Path(os.environ["HERMES_HOME"])
    )

    manager.discover_and_load(force=True)

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    state_a = raw["plugins"]["entries"]["owner-a"]["settings"]["login_backends"][
        "bitwarden"
    ]
    state_b = raw["plugins"]["entries"]["owner-b"]["settings"]["login_backends"][
        "bitwarden"
    ]
    assert state_a == {"enabled": False}
    assert state_b == {
        "enabled": True,
        "prior_stock": {"present": True, "value": "original-stock"},
    }
    assert raw["vault"]["bitwarden"]["enabled"] is False
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    ).owner_plugin_id == "owner-b"


@pytest.mark.parametrize(
    "managed_path",
    [
        "plugins.entries.owner-a.settings.login_backends.bitwarden.enabled",
        "plugins.entries.owner-a.settings.login_backends.bitwarden.prior_stock",
        "plugins.entries.owner-b.settings.login_backends.bitwarden.enabled",
        "plugins.entries.owner-b.settings.login_backends.bitwarden.prior_stock",
        "vault.bitwarden.enabled",
    ],
)
def test_force_reload_handoff_rejects_managed_paths_without_mutation(
    managed_path: str,
):
    from hermes_cli import managed_scope

    manager, config_path = _prepare_different_owner_handoff(
        Path(os.environ["HERMES_HOME"])
    )
    before = config_path.read_bytes()
    provider_before = login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager.scope_key
    )

    with patch.object(
        managed_scope, "is_key_managed", side_effect=lambda key: key == managed_path
    ), pytest.raises(PermissionError, match="administrator-managed"):
        manager.discover_and_load(force=True)

    assert config_path.read_bytes() == before
    assert (
        login_backend_registry.snapshot_registration(
            "bitwarden", scope=manager.scope_key
        )
        is provider_before
    )


def test_different_owner_handoff_later_unload_restores_original_stock():
    manager, config_path = _prepare_different_owner_handoff(
        Path(os.environ["HERMES_HOME"])
    )
    manager.discover_and_load(force=True)

    manager.unload("owner-b")

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert raw["vault"]["bitwarden"]["enabled"] == "original-stock"
    state_b = raw["plugins"]["entries"]["owner-b"]["settings"]["login_backends"][
        "bitwarden"
    ]
    assert state_b == {"enabled": False}


def test_different_owner_handoff_rejects_stale_snapshot_without_writing():
    manager, config_path = _prepare_different_owner_handoff(
        Path(os.environ["HERMES_HOME"])
    )
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["entries"]["owner-b"]["settings"]["login_backends"][
        "bitwarden"
    ]["prior_stock"] = {"present": True, "value": "stale-generation"}
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with pytest.raises(ValueError, match="stale"):
        manager.discover_and_load(force=True)

    assert config_path.read_bytes() == before


def test_different_owner_handoff_is_profile_isolated():
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    root = Path(os.environ["HERMES_HOME"]).parent
    home_a = root / "handoff-profile-a"
    home_b = root / "handoff-profile-b"
    token_a = set_hermes_home_override(home_a)
    try:
        manager_a, config_a = _prepare_different_owner_handoff(home_a)
    finally:
        reset_hermes_home_override(token_a)
    token_b = set_hermes_home_override(home_b)
    try:
        _, config_b = _prepare_different_owner_handoff(home_b)
        before_b = config_b.read_bytes()
    finally:
        reset_hermes_home_override(token_b)

    manager_a.discover_and_load(force=True)

    raw_a = yaml.safe_load(config_a.read_text(encoding="utf-8"))
    assert raw_a["plugins"]["entries"]["owner-b"]["settings"]["login_backends"][
        "bitwarden"
    ]["prior_stock"]["value"] == "original-stock"
    assert config_b.read_bytes() == before_b


def test_repeated_cleanup_does_not_overwrite_later_user_change():
    manager, _, config_path = _active_dual_replacement_manager(
        Path(os.environ["HERMES_HOME"])
    )
    manager.unload("dual-broker")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["vault"]["bitwarden"]["enabled"] = "later-user-value"
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    assert manager.unload("dual-broker") is False

    assert config_path.read_bytes() == before


def test_targeted_unload_isolated_between_profiles():
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    root = Path(os.environ["HERMES_HOME"]).parent
    home_a = root / "replacement-profile-a"
    home_b = root / "replacement-profile-b"

    token_a = set_hermes_home_override(home_a)
    try:
        manager_a, _, config_a = _active_dual_replacement_manager(home_a)
    finally:
        reset_hermes_home_override(token_a)
    token_b = set_hermes_home_override(home_b)
    try:
        manager_b, _, config_b = _active_dual_replacement_manager(home_b)
        before_b = config_b.read_bytes()
    finally:
        reset_hermes_home_override(token_b)

    manager_a.unload("dual-broker")

    _assert_bitwarden_replacement_cleaned(config_a)
    assert config_b.read_bytes() == before_b
    assert login_backend_registry.snapshot_registration(
        "bitwarden", scope=manager_b.scope_key
    ) is not None


@pytest.mark.parametrize(
    "managed_path",
    [
        "plugins.entries.broker-plugin.settings.login_backends.bitwarden.enabled",
        "plugins.entries.broker-plugin.settings.login_backends.bitwarden.prior_stock",
        "vault.bitwarden.enabled",
    ],
)
def test_replacement_activation_rejects_managed_paths_without_writing(
    managed_path: str,
):
    from hermes_cli import managed_scope

    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"
    before = path.read_bytes()

    with patch.object(
        managed_scope, "is_key_managed", side_effect=lambda key: key == managed_path
    ), pytest.raises(PermissionError, match="administrator-managed"):
        module.set_active("bitwarden", True)

    assert path.read_bytes() == before


def test_replacement_activation_rejects_managed_install_without_writing():
    from hermes_cli import config as config_mod

    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"
    before = path.read_bytes()

    with patch.object(config_mod, "is_managed", return_value=True), pytest.raises(
        PermissionError, match="managed install"
    ):
        module.set_active("bitwarden", True)

    assert path.read_bytes() == before


def test_replacement_activation_parse_failure_leaves_config_unchanged():
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"
    broken = "plugins:\n  entries: [unterminated\n"
    path.write_text(broken, encoding="utf-8")

    with pytest.raises(Exception, match="while parsing|expected"):
        module.set_active("bitwarden", True)

    assert path.read_text(encoding="utf-8") == broken


def _replacement_activation_subject() -> tuple[object, Path]:
    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
        vault={"bitwarden": {"enabled": True}},
    )
    manager = PluginManager()
    manager.discover_and_load()
    return manager._plugins["broker-plugin"].module, home / "config.yaml"


@pytest.mark.parametrize("active", [True, False])
@pytest.mark.parametrize(
    ("path", "malformed"),
    [
        ((), []),
        (("plugins",), []),
        (("plugins", "entries"), "entries"),
        (("plugins", "entries", "broker-plugin"), 1),
        (("plugins", "entries", "broker-plugin", "settings"), []),
        (
            (
                "plugins",
                "entries",
                "broker-plugin",
                "settings",
                "login_backends",
            ),
            [],
        ),
        (
            (
                "plugins",
                "entries",
                "broker-plugin",
                "settings",
                "login_backends",
                "bitwarden",
            ),
            [],
        ),
        (("vault",), "vault"),
        (("vault", "bitwarden"), []),
    ],
)
def test_replacement_activation_rejects_malformed_relevant_parent_without_writing(
    path: tuple[str, ...],
    malformed: object,
    active: bool,
):
    from hermes_cli import config as config_mod

    module, config_path = _replacement_activation_subject()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if path:
        node = raw
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = malformed
    else:
        raw = malformed
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with patch.object(config_mod, "save_config") as save_config, pytest.raises(
        TypeError, match="must be a mapping"
    ):
        module.set_active("bitwarden", active)

    save_config.assert_not_called()
    assert config_path.read_bytes() == before


@pytest.mark.parametrize("active", [True, False])
@pytest.mark.parametrize("malformed", [None, 0, "true", []])
def test_replacement_activation_rejects_malformed_active_value_without_writing(
    malformed: object,
    active: bool,
):
    from hermes_cli import config as config_mod

    module, config_path = _replacement_activation_subject()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    settings = raw["plugins"]["entries"]["broker-plugin"].setdefault("settings", {})
    state = settings.setdefault("login_backends", {}).setdefault("bitwarden", {})
    state["enabled"] = malformed
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with patch.object(config_mod, "save_config") as save_config, pytest.raises(
        TypeError, match="login_backends.bitwarden.enabled.*bool"
    ):
        module.set_active("bitwarden", active)

    save_config.assert_not_called()
    assert config_path.read_bytes() == before


@pytest.mark.parametrize("active", [True, False])
@pytest.mark.parametrize(
    "malformed",
    [
        [],
        {},
        {"present": "true"},
        {"present": True},
        {"present": False, "value": True},
        {"present": False, "unexpected": True},
        {"present": True, "value": False, "unexpected": True},
    ],
)
def test_replacement_activation_rejects_malformed_snapshot_without_writing(
    malformed: object,
    active: bool,
):
    from hermes_cli import config as config_mod

    module, config_path = _replacement_activation_subject()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    settings = raw["plugins"]["entries"]["broker-plugin"].setdefault("settings", {})
    state = settings.setdefault("login_backends", {}).setdefault("bitwarden", {})
    state["enabled"] = not active
    state["prior_stock"] = malformed
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    with patch.object(config_mod, "save_config") as save_config, pytest.raises(
        (TypeError, ValueError), match="login_backends.bitwarden.prior_stock"
    ):
        module.set_active("bitwarden", active)

    save_config.assert_not_called()
    assert config_path.read_bytes() == before


def test_replacement_activation_ignores_unrelated_malformed_section():
    module, config_path = _replacement_activation_subject()
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["display"] = []
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    module.set_active("bitwarden", True)

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["display"] == []
    assert saved["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]["enabled"] is True


def test_replacement_activation_save_failure_leaves_config_unchanged():
    from hermes_cli import config as config_mod

    home = Path(os.environ["HERMES_HOME"])
    _write_plugin(
        home,
        "broker-plugin",
        backend_name="bitwarden",
        display_name="Broker Bitwarden",
        prefix="bw:",
        replace_stock=True,
        class_name="BrokerBitwardenBackend",
    )
    _configure_plugins(
        home,
        ["broker-plugin"],
        grants={"broker-plugin": ["vault.login_backend_replace"]},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module
    path = home / "config.yaml"
    before = path.read_bytes()

    with patch.object(config_mod, "save_config", side_effect=OSError("disk full")), pytest.raises(
        OSError, match="disk full"
    ):
        module.set_active("bitwarden", True)

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("backend_name", "replace_stock"),
    [("broker", False), ("bitwarden", True)],
)
def test_plugin_cannot_activate_unowned_or_nonreplacement_backend(
    backend_name: str,
    replace_stock: bool,
):
    home = Path(os.environ["HERMES_HOME"])
    owner = "owner-plugin" if replace_stock else "caller-plugin"
    _write_plugin(
        home,
        owner,
        backend_name=backend_name,
        display_name="Owned backend",
        prefix="bw:" if replace_stock else "broker:",
        replace_stock=replace_stock,
        class_name="OwnedBackend",
    )
    plugin_ids = [owner]
    grants = {owner: ["vault.login_backend_replace"]} if replace_stock else {}
    if replace_stock:
        _write_plugin(
            home,
            "caller-plugin",
            backend_name="caller",
            display_name="Caller backend",
            prefix="caller:",
        )
        plugin_ids.append("caller-plugin")
    _configure_plugins(home, plugin_ids, grants=grants)
    manager = PluginManager()
    manager.discover_and_load()
    caller = manager._plugins["caller-plugin"].module

    with pytest.raises(ValueError, match="owned active stock replacement"):
        caller.set_active(backend_name, True)


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
    module = manager._plugins["broker-bitwarden"].module
    module.set_active("bitwarden", True)

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
