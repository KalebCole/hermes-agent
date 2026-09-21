"""Profile-scoped registry for login-backend providers."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from agent.vault_backends.base import LoginBackend
from hermes_constants import hermes_home_key

LoginBackendFactory = Callable[[Mapping[str, Any]], LoginBackend]


@dataclass(frozen=True)
class LoginBackendProvider:
    name: str
    display_name: str
    prefix: str
    needs_unlock: bool
    factory: LoginBackendFactory
    replaces_stock: bool = False

    def create(self, config: Mapping[str, Any]) -> LoginBackend:
        backend = self.factory(config)
        if not isinstance(backend, LoginBackend):
            raise TypeError(f"login backend factory {self.name!r} did not return LoginBackend")
        if backend.name != self.name or backend.prefix != self.prefix:
            raise ValueError(
                f"login backend factory {self.name!r} returned inconsistent public metadata"
            )
        return backend


_providers_by_scope: dict[str, dict[str, LoginBackendProvider]] = {}
_prefixes_by_scope: dict[str, dict[str, LoginBackendProvider]] = {}
_lock = threading.Lock()


def prefixes_overlap(first: str, second: str) -> bool:
    return first.startswith(second) or second.startswith(first)


def _validate_provider(provider: LoginBackendProvider) -> None:
    if not isinstance(provider, LoginBackendProvider):
        raise TypeError(
            "register_provider() expects a LoginBackendProvider instance, "
            f"got {type(provider).__name__}"
        )
    if (
        not isinstance(provider.name, str)
        or not provider.name.strip()
        or provider.name != provider.name.strip()
        or provider.name != provider.name.lower()
    ):
        raise ValueError("backend name must be a non-empty lowercase string")
    if not isinstance(provider.prefix, str) or not provider.prefix.strip():
        raise ValueError("handle prefix must be a non-empty string")
    if not callable(provider.factory):
        raise TypeError("login backend factory must be callable")


def register_provider(provider: LoginBackendProvider, *, scope: str) -> None:
    """Register *provider* in exactly one profile scope."""
    _validate_provider(provider)
    with _lock:
        providers = _providers_by_scope.get(scope, {})
        prefixes = _prefixes_by_scope.get(scope, {})
        if provider.name in providers:
            raise ValueError(f"backend name {provider.name!r} is already registered")
        if provider.prefix in prefixes:
            raise ValueError(f"handle prefix {provider.prefix!r} is already registered")
        overlapping_prefix = next(
            (
                registered_prefix
                for registered_prefix in prefixes
                if prefixes_overlap(provider.prefix, registered_prefix)
            ),
            None,
        )
        if overlapping_prefix is not None:
            raise ValueError(
                f"handle prefix {provider.prefix!r} overlaps registered prefix "
                f"{overlapping_prefix!r}"
            )
        if scope not in _providers_by_scope:
            providers = _providers_by_scope.setdefault(scope, {})
            prefixes = _prefixes_by_scope.setdefault(scope, {})
        providers[provider.name] = provider
        prefixes[provider.prefix] = provider


def list_providers(*, scope: str | None = None) -> list[LoginBackendProvider]:
    """Return providers registered for *scope*, sorted by backend name."""
    active_scope = scope if scope is not None else hermes_home_key()
    with _lock:
        return sorted(
            _providers_by_scope.get(active_scope, {}).values(),
            key=lambda provider: provider.name,
        )


def snapshot_registration(name: str, *, scope: str) -> LoginBackendProvider | None:
    """Return the provider currently occupying *name* in *scope*."""
    with _lock:
        return _providers_by_scope.get(scope, {}).get(name)


def restore_registration(
    name: str,
    current: LoginBackendProvider,
    previous: LoginBackendProvider | None,
    *,
    scope: str,
) -> bool:
    """Restore *previous* only while *current* still owns the name slot."""
    with _lock:
        providers = _providers_by_scope.get(scope)
        if providers is None or providers.get(name) is not current:
            return False

        prefixes = _prefixes_by_scope.get(scope, {})
        if prefixes.get(current.prefix) is not current:
            return False
        if previous is not None:
            previous_prefix_owner = prefixes.get(previous.prefix)
            if previous_prefix_owner is not None and previous_prefix_owner is not current:
                return False

        providers.pop(name)
        prefixes.pop(current.prefix)
        if previous is not None:
            providers[name] = previous
            prefixes[previous.prefix] = previous

        if not providers:
            _providers_by_scope.pop(scope, None)
        if not prefixes:
            _prefixes_by_scope.pop(scope, None)
        return True


def _reset_for_tests() -> None:
    """Clear all registrations. Test-only."""
    with _lock:
        _providers_by_scope.clear()
        _prefixes_by_scope.clear()
