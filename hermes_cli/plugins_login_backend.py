"""Persisted activation and unload reconciliation for plugin login backends."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from hermes_cli.plugins_state import _locked_plugin_state

if TYPE_CHECKING:
    from hermes_cli.plugins_ledger import PluginRegistration


@dataclass(frozen=True)
class LoginBackendCarryover:
    plugin_id: str
    backend_name: str
    scope: str
    prior_stock: dict[str, Any]


def state_paths(
    plugin_id: str, backend_name: str
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    state_path = (
        "plugins",
        "entries",
        plugin_id,
        "settings",
        "login_backends",
        backend_name,
    )
    return (
        state_path + ("enabled",),
        state_path + ("prior_stock",),
        ("vault", backend_name, "enabled"),
    )


def raw_value(raw: Mapping[str, Any], path: tuple[str, ...], missing: object) -> Any:
    node: Any = raw
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return missing
        node = node[key]
    return node


def validate_snapshot(
    snapshot: Any, rollback_path: tuple[str, ...], missing: object
) -> None:
    rollback_name = ".".join(rollback_path)
    if not isinstance(snapshot, Mapping):
        raise TypeError(
            f"Login backend snapshot {rollback_name!r} must be a mapping"
        )
    present = snapshot.get("present", missing)
    if type(present) is not bool:
        raise TypeError(
            f"Login backend snapshot {rollback_name!r} must contain "
            "a bool 'present'"
        )
    expected_keys = {"present", "value"} if present else {"present"}
    if set(snapshot) != expected_keys:
        value_rule = (
            "contain exactly 'present' and 'value'"
            if present
            else "contain only 'present'"
        )
        raise ValueError(
            f"Login backend snapshot {rollback_name!r} must {value_rule}"
        )


def set_raw_value(raw: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    node = raw
    for key in path[:-1]:
        child = node.get(key)
        if child is None:
            child = {}
            node[key] = child
        node = child
    node[path[-1]] = value


def set_active(plugin_id: str, backend_name: str, active: bool) -> None:
    from hermes_cli import config as config_mod
    from hermes_cli import managed_scope

    active_path, rollback_path, vault_path = state_paths(plugin_id, backend_name)
    config_path = config_mod.get_config_path()
    with _locked_plugin_state(config_path), config_mod._CONFIG_LOCK:
        if config_mod.is_managed():
            raise PermissionError(
                "Login backend activation cannot be changed in a managed install"
            )
        for path in (active_path, rollback_path, vault_path):
            dotted_path = ".".join(path)
            if managed_scope.is_key_managed(dotted_path):
                raise PermissionError(
                    f"Login backend setting {dotted_path!r} is administrator-managed"
                )
        try:
            raw = config_mod.require_readable_config_before_write(config_path)
        except RuntimeError as exc:
            if isinstance(exc.__cause__, TypeError):
                raise TypeError(
                    "Login backend activation config root must be a mapping"
                ) from exc
            raise
        missing = object()

        def validate_parent_path(path: tuple[str, ...]) -> None:
            node: Any = raw
            traversed: list[str] = []
            for key in path:
                if not isinstance(node, Mapping):
                    dotted_path = ".".join(traversed) or "<config root>"
                    raise TypeError(
                        f"Login backend activation path {dotted_path!r} "
                        "must be a mapping"
                    )
                if key not in node:
                    return
                node = node[key]
                traversed.append(key)
            if not isinstance(node, Mapping):
                dotted_path = ".".join(traversed)
                raise TypeError(
                    f"Login backend activation path {dotted_path!r} "
                    "must be a mapping"
                )

        for path in (active_path[:-1], rollback_path[:-1], vault_path[:-1]):
            validate_parent_path(path)

        current = raw_value(raw, active_path, missing)
        if current is not missing and type(current) is not bool:
            raise TypeError(
                f"Login backend setting {'.'.join(active_path)!r} must be a bool"
            )

        snapshot = raw_value(raw, rollback_path, missing)
        if snapshot is not missing:
            validate_snapshot(snapshot, rollback_path, missing)

        if current is active:
            return

        if active:
            stock_value = raw_value(raw, vault_path, missing)
            snapshot = {"present": stock_value is not missing}
            if stock_value is not missing:
                snapshot["value"] = stock_value
            set_raw_value(raw, rollback_path, snapshot)
            set_raw_value(raw, active_path, True)
            set_raw_value(raw, vault_path, False)
        else:
            set_raw_value(raw, active_path, False)
            if snapshot is not missing:
                if snapshot["present"]:
                    set_raw_value(raw, vault_path, snapshot["value"])
                else:
                    vault_section = raw_value(raw, vault_path[:-1], missing)
                    if isinstance(vault_section, dict):
                        vault_section.pop(vault_path[-1], None)
                state = raw_value(raw, rollback_path[:-1], missing)
                if isinstance(state, dict):
                    state.pop(rollback_path[-1], None)

        config_mod.save_config(raw, strip_defaults=False)


def capture_carryovers(
    manager: Any, registrations: list[PluginRegistration]
) -> list[LoginBackendCarryover]:
    from agent.vault_backends import registry as login_backend_registry
    from hermes_cli import config as config_mod

    candidates = [
        registration
        for registration in registrations
        if registration.kind == "login_backend"
        and registration.metadata is not None
        and registration.metadata.replaces_stock
    ]
    if not candidates:
        return []
    try:
        raw = config_mod.require_readable_config_before_write(
            config_mod.get_config_path()
        )
    except Exception:
        return []
    missing = object()
    carryovers: list[LoginBackendCarryover] = []
    for registration in candidates:
        provider = registration.metadata
        if (
            login_backend_registry.snapshot_registration(
                provider.name, scope=manager.scope_key
            )
            is not provider
        ):
            continue
        active_path, rollback_path, _ = state_paths(
            provider.owner_plugin_id, provider.name
        )
        if raw_value(raw, active_path, missing) is not True:
            continue
        snapshot = raw_value(raw, rollback_path, missing)
        try:
            validate_snapshot(snapshot, rollback_path, missing)
        except (TypeError, ValueError):
            continue
        carryovers.append(
            LoginBackendCarryover(
                plugin_id=provider.owner_plugin_id,
                backend_name=provider.name,
                scope=manager.scope_key,
                prior_stock=copy.deepcopy(dict(snapshot)),
            )
        )
    return carryovers


def restore_carryovers(
    carryovers: list[LoginBackendCarryover],
    *,
    preserve_reregistered: bool,
) -> None:
    from agent.vault_backends import registry as login_backend_registry
    from hermes_cli import config as config_mod

    if not carryovers:
        return
    config_path = config_mod.get_config_path()
    with _locked_plugin_state(config_path), config_mod._CONFIG_LOCK:
        raw = config_mod.require_readable_config_before_write(config_path)
        missing = object()
        changed = False
        for carryover in carryovers:
            current_provider = login_backend_registry.snapshot_registration(
                carryover.backend_name, scope=carryover.scope
            )
            active_path, rollback_path, vault_path = state_paths(
                carryover.plugin_id, carryover.backend_name
            )
            current_active = raw_value(raw, active_path, missing)
            current_snapshot = raw_value(raw, rollback_path, missing)
            if (
                preserve_reregistered
                and current_provider is not None
                and current_provider.replaces_stock
                and current_provider.owner_plugin_id == carryover.plugin_id
                and current_active is True
                and current_snapshot == carryover.prior_stock
            ):
                continue
            if (
                current_active is not True
                or current_snapshot != carryover.prior_stock
            ):
                continue
            set_raw_value(raw, active_path, False)
            if carryover.prior_stock["present"]:
                set_raw_value(raw, vault_path, carryover.prior_stock["value"])
            else:
                vault_section = raw_value(raw, vault_path[:-1], missing)
                if isinstance(vault_section, dict):
                    vault_section.pop(vault_path[-1], None)
            state = raw_value(raw, rollback_path[:-1], missing)
            if isinstance(state, dict):
                state.pop(rollback_path[-1], None)
            changed = True
        if changed:
            config_mod.save_config(raw, strip_defaults=False)
