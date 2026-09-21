"""Plugin disable/remove restores persisted stock-login-backend leases."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from hermes_cli import plugins_cmd


def _write_active_lease(
    home: Path,
    *,
    plugin_id: str = "broker-plugin",
    plugin_disabled: bool = False,
) -> Path:
    plugin_dir = home / "plugins" / plugin_id
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.yaml").write_text(
        yaml.safe_dump({"name": plugin_id, "version": "0.1.0"}),
        encoding="utf-8",
    )
    (plugin_dir / "__init__.py").write_text(
        "def register(ctx): pass\n", encoding="utf-8"
    )
    config_path = home / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "plugins": {
                    "enabled": [] if plugin_disabled else [plugin_id],
                    "disabled": [plugin_id] if plugin_disabled else [],
                    "entries": {
                        plugin_id: {
                            "settings": {
                                "login_backends": {
                                    "bitwarden": {
                                        "enabled": True,
                                        "prior_stock": {
                                            "present": True,
                                            "value": "original-stock",
                                        },
                                    }
                                },
                                "unrelated": "keep",
                            }
                        }
                    },
                },
                "vault": {
                    "bitwarden": {
                        "enabled": False,
                        "endpoint": "https://vault.invalid",
                    }
                },
                "display": {"skin": "slate"},
            }
        ),
        encoding="utf-8",
    )
    return config_path


def _assert_lease_restored(config_path: Path) -> None:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    state = raw["plugins"]["entries"]["broker-plugin"]["settings"][
        "login_backends"
    ]["bitwarden"]
    assert state == {"enabled": False}
    assert raw["vault"]["bitwarden"] == {
        "enabled": "original-stock",
        "endpoint": "https://vault.invalid",
    }
    assert raw["plugins"]["entries"]["broker-plugin"]["settings"]["unrelated"] == "keep"
    assert raw["display"] == {"skin": "slate"}


def test_cli_disable_restores_persisted_lease_without_live_manager():
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)

    plugins_cmd.cmd_disable("broker-plugin")

    _assert_lease_restored(config_path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert raw["plugins"]["enabled"] == []
    assert raw["plugins"]["disabled"] == ["broker-plugin"]


def test_cli_remove_restores_persisted_lease_before_deleting_plugin():
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)

    plugins_cmd.cmd_remove("broker-plugin")

    _assert_lease_restored(config_path)
    assert not (home / "plugins" / "broker-plugin").exists()


def test_dashboard_disable_restores_already_disabled_active_lease_idempotently():
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home, plugin_disabled=True)

    first = plugins_cmd.dashboard_set_agent_plugin_enabled(
        "broker-plugin", enabled=False
    )
    after_first = config_path.read_bytes()
    second = plugins_cmd.dashboard_set_agent_plugin_enabled(
        "broker-plugin", enabled=False
    )

    assert first == {"ok": True, "name": "broker-plugin", "unchanged": True}
    assert second == {"ok": True, "name": "broker-plugin", "unchanged": True}
    assert config_path.read_bytes() == after_first
    _assert_lease_restored(config_path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert raw["plugins"]["entries"]["broker-plugin"][
        "login_backend_generation"
    ] == 1


def test_dashboard_remove_restores_persisted_lease_before_deleting_plugin():
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)

    result = plugins_cmd.dashboard_remove_user_plugin("broker-plugin")

    assert result == {"ok": True, "name": "broker-plugin"}
    _assert_lease_restored(config_path)
    assert not (home / "plugins" / "broker-plugin").exists()


@pytest.mark.parametrize("action", ["cli-disable", "cli-remove", "dashboard-disable", "dashboard-remove"])
def test_disable_remove_aborts_on_malformed_lease_without_mutation(action: str):
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["entries"]["broker-plugin"]["settings"]["login_backends"][
        "bitwarden"
    ]["prior_stock"] = {"present": True}
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    if action == "cli-disable":
        with pytest.raises(SystemExit):
            plugins_cmd.cmd_disable("broker-plugin")
    elif action == "cli-remove":
        with pytest.raises(SystemExit):
            plugins_cmd.cmd_remove("broker-plugin")
    elif action == "dashboard-disable":
        result = plugins_cmd.dashboard_set_agent_plugin_enabled(
            "broker-plugin", enabled=False
        )
        assert result["ok"] is False
    else:
        result = plugins_cmd.dashboard_remove_user_plugin("broker-plugin")
        assert result["ok"] is False

    assert config_path.read_bytes() == before
    assert (home / "plugins" / "broker-plugin").exists()


def test_cli_disable_aborts_on_unreadable_config_without_mutation():
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)
    broken = "plugins:\n  entries: [unterminated\n"
    config_path.write_text(broken, encoding="utf-8")

    with patch.object(plugins_cmd, "_resolve_plugin_key", return_value="broker-plugin"):
        with pytest.raises(SystemExit):
            plugins_cmd.cmd_disable("broker-plugin")

    assert config_path.read_text(encoding="utf-8") == broken


def test_disable_restoration_uses_current_profile_only():
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    root = Path(os.environ["HERMES_HOME"]).parent
    home_a = root / "cleanup-profile-a"
    home_b = root / "cleanup-profile-b"
    config_a = _write_active_lease(home_a)
    config_b = _write_active_lease(home_b)
    before_b = config_b.read_bytes()

    token = set_hermes_home_override(home_a)
    try:
        plugins_cmd.cmd_disable("broker-plugin")
    finally:
        reset_hermes_home_override(token)

    _assert_lease_restored(config_a)
    assert config_b.read_bytes() == before_b


@pytest.mark.parametrize(
    "action", ["cli-disable", "cli-remove", "dashboard-disable", "dashboard-remove"]
)
@pytest.mark.parametrize("malformed", [True, -1, "1"])
def test_disable_remove_rejects_malformed_generation_without_mutation(
    action: str, malformed
):
    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["plugins"]["entries"]["broker-plugin"][
        "login_backend_generation"
    ] = malformed
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = config_path.read_bytes()

    if action == "cli-disable":
        with pytest.raises(SystemExit):
            plugins_cmd.cmd_disable("broker-plugin")
    elif action == "cli-remove":
        with pytest.raises(SystemExit):
            plugins_cmd.cmd_remove("broker-plugin")
    elif action == "dashboard-disable":
        result = plugins_cmd.dashboard_set_agent_plugin_enabled(
            "broker-plugin", enabled=False
        )
        assert result["ok"] is False
    else:
        result = plugins_cmd.dashboard_remove_user_plugin("broker-plugin")
        assert result["ok"] is False

    assert config_path.read_bytes() == before
    assert (home / "plugins" / "broker-plugin").exists()


@pytest.mark.parametrize(
    "action", ["cli-disable", "cli-remove", "dashboard-disable", "dashboard-remove"]
)
def test_disable_remove_rejects_managed_generation_without_restoring_lease(
    action: str,
):
    from hermes_cli import managed_scope

    home = Path(os.environ["HERMES_HOME"])
    config_path = _write_active_lease(home)
    before = config_path.read_bytes()
    generation_path = (
        "plugins.entries.broker-plugin.login_backend_generation"
    )

    with patch.object(
        managed_scope,
        "is_key_managed",
        side_effect=lambda key: key == generation_path,
    ):
        if action == "cli-disable":
            with pytest.raises(SystemExit):
                plugins_cmd.cmd_disable("broker-plugin")
        elif action == "cli-remove":
            with pytest.raises(SystemExit):
                plugins_cmd.cmd_remove("broker-plugin")
        elif action == "dashboard-disable":
            result = plugins_cmd.dashboard_set_agent_plugin_enabled(
                "broker-plugin", enabled=False
            )
            assert result["ok"] is False
        else:
            result = plugins_cmd.dashboard_remove_user_plugin("broker-plugin")
            assert result["ok"] is False

    assert config_path.read_bytes() == before
    assert (home / "plugins" / "broker-plugin").exists()
