"""Persisted activation and unload reconciliation for plugin login backends."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hermes_cli.plugins_state import _locked_plugin_state

if TYPE_CHECKING:
    from hermes_cli.plugins_ledger import PluginRegistration
    from hermes_cli.plugins_manifest import PluginManifest

_REPLACEABLE_STOCK_BACKENDS = frozenset({"onepassword", "bitwarden"})
_GENERATION_KEY = "login_backend_generation"


@dataclass(frozen=True)
class LoginBackendCarryover:
    plugin_id: str
    backend_name: str
    scope: str
    prior_stock: dict[str, Any]


@dataclass(frozen=True)
class _CarryoverAction:
    active_path: tuple[str, ...]
    rollback_path: tuple[str, ...]
    vault_path: tuple[str, ...]
    prior_stock: dict[str, Any]
    new_rollback_path: tuple[str, ...] | None = None


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


def generation_path(plugin_id: str) -> tuple[str, ...]:
    return ("plugins", "entries", plugin_id, _GENERATION_KEY)


def _generation_from_raw(raw: Mapping[str, Any], plugin_id: str) -> int:
    path = generation_path(plugin_id)
    _validate_parent_path(raw, path[:-1])
    missing = object()
    generation = raw_value(raw, path, missing)
    if generation is missing:
        return 0
    if type(generation) is not int or generation < 0:
        raise ValueError(
            f"Login backend generation {'.'.join(path)!r} must be a "
            "non-negative integer"
        )
    return generation


def read_generation(plugin_id: str) -> int:
    """Read the host-owned activation generation for the active profile."""
    from hermes_cli import config as config_mod

    config_path = config_mod.get_config_path()
    with _locked_plugin_state(config_path), config_mod._CONFIG_LOCK:
        raw = config_mod.require_readable_config_before_write(config_path)
        return _generation_from_raw(raw, plugin_id)


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


def _validate_parent_path(raw: Mapping[str, Any], path: tuple[str, ...]) -> None:
    node: Any = raw
    traversed: list[str] = []
    for key in path:
        if not isinstance(node, Mapping):
            dotted_path = ".".join(traversed) or "<config root>"
            raise TypeError(
                f"Login backend activation path {dotted_path!r} must be a mapping"
            )
        if key not in node:
            return
        node = node[key]
        traversed.append(key)
    if not isinstance(node, Mapping):
        dotted_path = ".".join(traversed)
        raise TypeError(
            f"Login backend activation path {dotted_path!r} must be a mapping"
        )


def _reject_managed_writes(paths: set[tuple[str, ...]]) -> None:
    from hermes_cli import config as config_mod
    from hermes_cli import managed_scope

    if config_mod.is_managed():
        raise PermissionError(
            "Login backend activation cannot be changed in a managed install"
        )
    for path in sorted(paths):
        dotted_path = ".".join(path)
        if managed_scope.is_key_managed(dotted_path):
            raise PermissionError(
                f"Login backend setting {dotted_path!r} is administrator-managed"
            )


def _validate_carryover_policy(carryovers: list[LoginBackendCarryover]) -> None:
    """Reject a force reload before registrations move if reconciliation may be managed."""
    from hermes_cli import config as config_mod

    if not carryovers:
        return
    raw = config_mod.require_readable_config_before_write(
        config_mod.get_config_path()
    )
    missing = object()
    paths: set[tuple[str, ...]] = set()
    entries = raw_value(raw, ("plugins", "entries"), missing)
    for carryover in carryovers:
        active_path, rollback_path, vault_path = state_paths(
            carryover.plugin_id, carryover.backend_name
        )
        paths.update({active_path, rollback_path, vault_path})
        if not isinstance(entries, Mapping):
            continue
        for plugin_id in entries:
            if plugin_id == carryover.plugin_id:
                continue
            new_active_path, new_rollback_path, _ = state_paths(
                str(plugin_id), carryover.backend_name
            )
            if raw_value(raw, new_active_path, missing) is True:
                paths.update({new_active_path, new_rollback_path})
    _reject_managed_writes(paths)


def _active_leases(
    raw: Mapping[str, Any], plugin_id: str
) -> list[
    tuple[
        tuple[str, ...],
        tuple[str, ...],
        tuple[str, ...],
        Mapping[str, Any],
    ]
]:
    missing = object()
    backends_path = (
        "plugins",
        "entries",
        plugin_id,
        "settings",
        "login_backends",
    )
    _validate_parent_path(raw, backends_path)
    backends = raw_value(raw, backends_path, missing)
    if backends is missing:
        return []
    active_leases = []
    for backend_name, state in backends.items():
        if not isinstance(state, Mapping):
            raise TypeError(
                f"Login backend activation path "
                f"{'.'.join(backends_path + (str(backend_name),))!r} "
                "must be a mapping"
            )
        active_path, rollback_path, vault_path = state_paths(
            plugin_id, str(backend_name)
        )
        active = raw_value(raw, active_path, missing)
        if active is not missing and type(active) is not bool:
            raise TypeError(
                f"Login backend setting {'.'.join(active_path)!r} must be a bool"
            )
        snapshot = raw_value(raw, rollback_path, missing)
        if snapshot is not missing:
            validate_snapshot(snapshot, rollback_path, missing)
        if active is not True:
            continue
        if backend_name not in _REPLACEABLE_STOCK_BACKENDS:
            raise ValueError(
                f"Login backend lease {backend_name!r} is not a replaceable "
                "stock backend"
            )
        if snapshot is missing:
            validate_snapshot(snapshot, rollback_path, missing)
        _validate_parent_path(raw, vault_path[:-1])
        active_leases.append(
            (active_path, rollback_path, vault_path, snapshot)
        )
    return active_leases


def _restore_leases_in_raw(
    raw: dict[str, Any],
    active_leases: list[
        tuple[
            tuple[str, ...],
            tuple[str, ...],
            tuple[str, ...],
            Mapping[str, Any],
        ]
    ],
) -> None:
    missing = object()
    for active_path, rollback_path, vault_path, snapshot in active_leases:
        set_raw_value(raw, active_path, False)
        if snapshot["present"]:
            set_raw_value(raw, vault_path, snapshot["value"])
        else:
            vault_section = raw_value(raw, vault_path[:-1], missing)
            if isinstance(vault_section, dict):
                vault_section.pop(vault_path[-1], None)
        state = raw_value(raw, rollback_path[:-1], missing)
        if isinstance(state, dict):
            state.pop(rollback_path[-1], None)


def _config_name_set(raw: Mapping[str, Any], key: str) -> set[str]:
    plugins = raw.get("plugins")
    value = plugins.get(key) if isinstance(plugins, Mapping) else None
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def disable_plugin(plugin_id: str) -> bool:
    """Durably disable one plugin and revoke all loaded login-backend contexts."""
    from hermes_cli import config as config_mod

    config_path = config_mod.get_config_path()
    with _locked_plugin_state(config_path), config_mod._CONFIG_LOCK:
        raw = config_mod.require_readable_config_before_write(config_path)
        generation = _generation_from_raw(raw, plugin_id)
        active_leases = _active_leases(raw, plugin_id)
        enabled = _config_name_set(raw, "enabled")
        disabled = _config_name_set(raw, "disabled")
        already_disabled = plugin_id not in enabled and plugin_id in disabled
        if already_disabled and not active_leases:
            return False

        writable_paths = {
            generation_path(plugin_id),
            ("plugins", "enabled"),
            ("plugins", "disabled"),
        }
        writable_paths.update(
            path
            for active_path, rollback_path, vault_path, _ in active_leases
            for path in (active_path, rollback_path, vault_path)
        )
        _reject_managed_writes(writable_paths)
        _restore_leases_in_raw(raw, active_leases)
        set_raw_value(raw, generation_path(plugin_id), generation + 1)
        enabled.discard(plugin_id)
        enabled.discard(plugin_id.split("/")[-1])
        disabled.add(plugin_id)
        plugins = raw.setdefault("plugins", {})
        if not isinstance(plugins, dict):
            raise TypeError("Plugin config path 'plugins' must be a mapping")
        plugins["enabled"] = sorted(enabled)
        plugins["disabled"] = sorted(disabled)
        config_mod.save_config(raw, strip_defaults=False)
        return not already_disabled


def revoke_plugin(plugin_id: str) -> None:
    """Revoke loaded contexts and restore leases before removing a plugin tree."""
    from hermes_cli import config as config_mod

    config_path = config_mod.get_config_path()
    with _locked_plugin_state(config_path), config_mod._CONFIG_LOCK:
        raw = config_mod.require_readable_config_before_write(config_path)
        generation = _generation_from_raw(raw, plugin_id)
        active_leases = _active_leases(raw, plugin_id)
        writable_paths = {generation_path(plugin_id)}
        writable_paths.update(
            path
            for active_path, rollback_path, vault_path, _ in active_leases
            for path in (active_path, rollback_path, vault_path)
        )
        _reject_managed_writes(writable_paths)
        _restore_leases_in_raw(raw, active_leases)
        set_raw_value(raw, generation_path(plugin_id), generation + 1)
        config_mod.save_config(raw, strip_defaults=False)


def _manifest_path_exists(manifest: PluginManifest) -> bool:
    if manifest.source not in {"user", "project"}:
        return True
    if not manifest.path:
        return False
    plugin_path = Path(manifest.path)
    if not plugin_path.is_dir():
        return False
    native_manifest = any(
        candidate.exists()
        for candidate in (plugin_path / "plugin.yaml", plugin_path / "plugin.yml")
    )
    portable_manifest = plugin_path / "plugin.json"
    return (
        native_manifest
        or portable_manifest.exists()
        or portable_manifest.is_symlink()
    )


def _verify_activation_eligibility(
    raw: Mapping[str, Any],
    plugin_id: str,
    provider: Any,
    manifest: PluginManifest,
    scope: str,
) -> None:
    from agent.vault_backends import registry as login_backend_registry
    from hermes_constants import hermes_home_key
    from hermes_cli.plugin_capabilities import plugin_capability_granted
    from hermes_cli.plugins_discovery import (
        _get_disabled_plugins,
        _get_enabled_plugins,
        gate_manifest,
    )

    current = login_backend_registry.snapshot_registration(
        provider.name, scope=scope
    )
    if current is not provider:
        raise PermissionError("Login backend provider registration is no longer current")
    if hermes_home_key() != scope:
        raise PermissionError(
            "Login backend provider belongs to a different profile"
        )
    try:
        generation = _generation_from_raw(raw, plugin_id)
    except ValueError as exc:
        raise PermissionError(str(exc)) from exc
    if generation != provider.activation_generation:
        raise PermissionError("Login backend provider activation generation is revoked")
    verdict = gate_manifest(
        manifest, _get_disabled_plugins(), _get_enabled_plugins()
    )
    if verdict.action == "placeholder":
        raise PermissionError("Login backend provider plugin is no longer enabled")
    if not _manifest_path_exists(manifest):
        raise PermissionError("Login backend provider plugin path is no longer installed")
    if not plugin_capability_granted(
        plugin_id, "vault.login_backend_replace", config=raw
    ):
        raise PermissionError(
            "Login backend replacement capability is no longer granted"
        )


def set_active(
    plugin_id: str,
    backend_name: str,
    active: bool,
    *,
    provider: Any,
    manifest: PluginManifest,
    scope: str,
) -> None:
    from hermes_cli import config as config_mod

    active_path, rollback_path, vault_path = state_paths(plugin_id, backend_name)
    config_path = config_mod.get_config_path()
    with _locked_plugin_state(config_path), config_mod._CONFIG_LOCK:
        try:
            raw = config_mod.require_readable_config_before_write(config_path)
        except RuntimeError as exc:
            if isinstance(exc.__cause__, TypeError):
                raise TypeError(
                    "Login backend activation config root must be a mapping"
                ) from exc
            raise
        _verify_activation_eligibility(
            raw, plugin_id, provider, manifest, scope
        )
        _reject_managed_writes({active_path, rollback_path, vault_path})
        missing = object()

        for path in (active_path[:-1], rollback_path[:-1], vault_path[:-1]):
            _validate_parent_path(raw, path)

        current = raw_value(raw, active_path, missing)
        if current is not missing and type(current) is not bool:
            raise TypeError(
                f"Login backend setting {'.'.join(active_path)!r} must be a bool"
            )

        snapshot = raw_value(raw, rollback_path, missing)
        if snapshot is not missing:
            validate_snapshot(snapshot, rollback_path, missing)

        if active and current is True and snapshot is missing:
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
    current_candidates = []
    for registration in candidates:
        provider = registration.metadata
        if (
            login_backend_registry.snapshot_registration(
                provider.name, scope=manager.scope_key
            )
            is provider
        ):
            current_candidates.append(registration)
    if not current_candidates:
        return []
    raw = config_mod.require_readable_config_before_write(
        config_mod.get_config_path()
    )
    missing = object()
    carryovers: list[LoginBackendCarryover] = []
    for registration in current_candidates:
        provider = registration.metadata
        active_path, rollback_path, _ = state_paths(
            provider.owner_plugin_id, provider.name
        )
        for path in (active_path[:-1], rollback_path[:-1]):
            _validate_parent_path(raw, path)
        current_active = raw_value(raw, active_path, missing)
        if current_active is not missing and type(current_active) is not bool:
            raise TypeError(
                f"Login backend setting {'.'.join(active_path)!r} must be a bool"
            )
        snapshot = raw_value(raw, rollback_path, missing)
        if snapshot is not missing:
            validate_snapshot(snapshot, rollback_path, missing)
        if current_active is not True:
            continue
        validate_snapshot(snapshot, rollback_path, missing)
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
        actions: list[_CarryoverAction] = []
        writable_paths: set[tuple[str, ...]] = set()
        for carryover in carryovers:
            current_provider = login_backend_registry.snapshot_registration(
                carryover.backend_name, scope=carryover.scope
            )
            active_path, rollback_path, vault_path = state_paths(
                carryover.plugin_id, carryover.backend_name
            )
            validate_snapshot(carryover.prior_stock, rollback_path, missing)
            current_active = raw_value(raw, active_path, missing)
            current_snapshot = raw_value(raw, rollback_path, missing)
            if current_active is not missing and type(current_active) is not bool:
                raise TypeError(
                    f"Login backend setting {'.'.join(active_path)!r} must be a bool"
                )
            if current_snapshot is not missing:
                validate_snapshot(current_snapshot, rollback_path, missing)
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
                preserve_reregistered
                and current_provider is not None
                and current_provider.replaces_stock
                and current_provider.owner_plugin_id != carryover.plugin_id
            ):
                new_active_path, new_rollback_path, _ = state_paths(
                    current_provider.owner_plugin_id, carryover.backend_name
                )
                new_active = raw_value(raw, new_active_path, missing)
                if new_active is not missing and type(new_active) is not bool:
                    raise TypeError(
                        f"Login backend setting "
                        f"{'.'.join(new_active_path)!r} must be a bool"
                    )
                new_snapshot = raw_value(raw, new_rollback_path, missing)
                if new_snapshot is not missing:
                    validate_snapshot(new_snapshot, new_rollback_path, missing)
                if new_active is True:
                    validate_snapshot(new_snapshot, new_rollback_path, missing)
                    stock_value = raw_value(raw, vault_path, missing)
                    expected_snapshot: dict[str, Any] = {
                        "present": stock_value is not missing
                    }
                    if stock_value is not missing:
                        expected_snapshot["value"] = stock_value
                    if new_snapshot != expected_snapshot:
                        raise ValueError(
                            f"Login backend snapshot "
                            f"{'.'.join(new_rollback_path)!r} is stale"
                        )
                    writable_paths.update(
                        {
                            active_path,
                            rollback_path,
                            new_active_path,
                            new_rollback_path,
                            vault_path,
                        }
                    )
                    actions.append(
                        _CarryoverAction(
                            active_path=active_path,
                            rollback_path=rollback_path,
                            vault_path=vault_path,
                            prior_stock=carryover.prior_stock,
                            new_rollback_path=new_rollback_path,
                        )
                    )
                    continue
            if (
                current_active is not True
                or current_snapshot != carryover.prior_stock
            ):
                continue
            writable_paths.update({active_path, rollback_path, vault_path})
            actions.append(
                _CarryoverAction(
                    active_path=active_path,
                    rollback_path=rollback_path,
                    vault_path=vault_path,
                    prior_stock=carryover.prior_stock,
                )
            )

        if not actions:
            return
        _reject_managed_writes(writable_paths)

        for action in actions:
            set_raw_value(raw, action.active_path, False)
            state = raw_value(raw, action.rollback_path[:-1], missing)
            if isinstance(state, dict):
                state.pop(action.rollback_path[-1], None)
            if action.new_rollback_path is not None:
                set_raw_value(
                    raw,
                    action.new_rollback_path,
                    copy.deepcopy(action.prior_stock),
                )
                set_raw_value(raw, action.vault_path, False)
            elif action.prior_stock["present"]:
                set_raw_value(
                    raw,
                    action.vault_path,
                    action.prior_stock["value"],
                )
            else:
                vault_section = raw_value(raw, action.vault_path[:-1], missing)
                if isinstance(vault_section, dict):
                    vault_section.pop(action.vault_path[-1], None)

        config_mod.save_config(raw, strip_defaults=False)
