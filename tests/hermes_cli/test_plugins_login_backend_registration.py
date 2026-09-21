"""Real-discovery tests for plugin-provided browser login backends."""

from __future__ import annotations

import os
import json
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


def test_replacement_activation_transaction_preserves_unrelated_config():
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
        vault={"bitwarden": {"enabled": True, "endpoint": "https://vault.invalid"}},
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
        "login_backend_enabled": True,
        "unrelated": "keep",
    }
    assert active["vault"]["bitwarden"] == {
        "enabled": False,
        "endpoint": "https://vault.invalid",
    }
    assert active["display"] == {"skin": "slate"}

    module.set_active("bitwarden", False)
    inactive = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert inactive["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backend_enabled"
    ] is False
    assert inactive["vault"]["bitwarden"]["enabled"] is True


def test_replacement_selection_uses_owner_setting_not_stock_enabled_flag():
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
        vault={"bitwarden": {"enabled": False}},
    )
    manager = PluginManager()
    manager.discover_and_load()
    module = manager._plugins["broker-plugin"].module

    with patch("agent.vault_backends.base.is_installed", return_value=True):
        active = next(
            backend for backend in enabled_backends() if backend.name == "bitwarden"
        )
        assert active.display_name == "Broker Bitwarden"

        module.set_active("bitwarden", False)
        inactive = next(
            backend for backend in enabled_backends() if backend.name == "bitwarden"
        )
        assert inactive.display_name == "Bitwarden"


@pytest.mark.parametrize(
    "managed_path",
    [
        "plugins.entries.broker-plugin.settings.login_backend_enabled",
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
