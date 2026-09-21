"""Login-backend contract + registry for the browser credential vault.

A ``LoginBackend`` lists login metadata (never secrets) and resolves ONE
password at fill time. External managers (1Password, Bitwarden) additionally
need a per-session unlock; ``resolve_password`` raises ``UnlockRequired``
while locked so the tool can ask the surface to prompt. Handles are
namespaced by ``prefix`` so ``backend_for_handle`` needs no lookup table.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence

from agent.vault_store import VaultItemMeta

if TYPE_CHECKING:
    from agent.vault_backends.registry import LoginBackendProvider


class UnlockRequired(Exception):
    """The backend is locked for this session; the surface must prompt for the master password."""

    def __init__(self, backend: "LoginBackend"):
        super().__init__(f"{backend.display_name} is locked")
        self.backend = backend


class LoginBackend(ABC):
    name: str                # config key: local | onepassword | bitwarden
    display_name: str        # user-facing
    prefix: str              # handle prefix ("vault_", "op:", "bw:")
    needs_unlock: bool = False

    def owns(self, handle: str) -> bool:
        return handle.startswith(self.prefix)

    def is_unlocked(self) -> bool:
        return True

    def unlock_noninteractive(self) -> bool:
        """Try a backend-owned unlock or session refresh without user secret input."""
        return False

    @abstractmethod
    def list_items(self) -> List[VaultItemMeta]:
        """Metadata only. Locked external backends return [] (the agent sees a lock hint instead)."""

    @abstractmethod
    def get_meta(self, handle: str) -> Optional[VaultItemMeta]: ...

    @abstractmethod
    def resolve_password(self, handle: str) -> str:
        """Server-side only; raises ``UnlockRequired`` when locked."""

    def resolve_otp(self, handle: str) -> Optional[str]:
        """Current one-time code for a login that stores a TOTP seed, else None (the user is asked).
        Server-side only, like resolve_password."""
        return None

    def resolve_secret(self, handle: str) -> Dict[str, str]:
        """Full payload of a payment/address item (server-side only). External managers list only
        logins, so the base returns the password-only shape."""
        return {"password": self.resolve_password(handle)}


def run_with_stdin_secret(argv: Sequence[str], *, env: Dict[str, str], secret: str, timeout: float,
                          label: str) -> subprocess.CompletedProcess:
    """Run a manager CLI feeding *secret* on stdin (never argv, never env). Spawn/timeout → RuntimeError."""
    try:
        return subprocess.run(  # noqa: S603 — argv list, no shell
            list(argv), env=env, input=secret + "\n", capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} unlock timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to invoke {label}: {exc}") from exc


def run_with_secret_env(argv: Sequence[str], *, env: Dict[str, str], secret_env: str, secret: str, timeout: float,
                        label: str) -> subprocess.CompletedProcess:
    """Run a manager CLI whose non-interactive contract reads the secret from a named env var.
    The variable is set on the child's environment only (never argv, never our process)."""
    child_env = dict(env)
    child_env[secret_env] = secret
    try:
        return subprocess.run(  # noqa: S603 — argv list, no shell
            list(argv), env=child_env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} unlock timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to invoke {label}: {exc}") from exc


def _cfg() -> Dict:
    from hermes_cli.config import load_config_readonly
    cfg = load_config_readonly().get("vault") or {}
    return cfg if isinstance(cfg, dict) else {}


def _stock_backend_providers() -> tuple["LoginBackendProvider", ...]:
    from agent.vault_backends.bitwarden import BitwardenLoginBackend
    from agent.vault_backends.onepassword import OnePasswordLoginBackend
    from agent.vault_backends.registry import LoginBackendProvider

    return (
        LoginBackendProvider(
            name=OnePasswordLoginBackend.name,
            display_name=OnePasswordLoginBackend.display_name,
            prefix=OnePasswordLoginBackend.prefix,
            needs_unlock=OnePasswordLoginBackend.needs_unlock,
            factory=OnePasswordLoginBackend,
        ),
        LoginBackendProvider(
            name=BitwardenLoginBackend.name,
            display_name=BitwardenLoginBackend.display_name,
            prefix=BitwardenLoginBackend.prefix,
            needs_unlock=BitwardenLoginBackend.needs_unlock,
            factory=BitwardenLoginBackend,
        ),
    )


def available_backend_providers() -> tuple["LoginBackendProvider", ...]:
    """All available backend providers: stock (1Password, Bitwarden) with plugin overlays and additions.

    Stock providers may be replaced by plugin providers when replace_stock=True and capability is granted.
    Plugin providers not replacing stock are appended in sorted order.
    """
    from agent.vault_backends.registry import list_providers

    plugin_providers = list_providers()
    replacements = {
        provider.name: provider
        for provider in plugin_providers
        if provider.replaces_stock and _replacement_is_active(provider)
    }
    providers = [
        replacements.get(provider.name, provider)
        for provider in _stock_backend_providers()
    ]
    providers.extend(
        sorted(
            (
                provider
                for provider in plugin_providers
                if not provider.replaces_stock
            ),
            key=lambda provider: (provider.name, provider.prefix),
        )
    )
    return tuple(providers)


def _replacement_is_active(provider: "LoginBackendProvider") -> bool:
    if not provider.replaces_stock or provider.owner_plugin_id is None:
        return False
    from hermes_cli.config import load_config_readonly

    config = load_config_readonly() or {}
    plugins = config.get("plugins")
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    entry = entries.get(provider.owner_plugin_id) if isinstance(entries, dict) else None
    settings = entry.get("settings") if isinstance(entry, dict) else None
    return not (
        isinstance(settings, dict)
        and settings.get("login_backend_enabled") is False
    )


def is_installed(name: str) -> bool:
    """Is the manager CLI reachable — honouring a configured ``binary_path`` over PATH."""
    import shutil
    section = _cfg().get(name) or {}
    explicit = str(section.get("binary_path") or "") if isinstance(section, dict) else ""
    if explicit:
        return Path(explicit).is_file()
    if name == "onepassword":
        from agent.secret_sources.onepassword import find_op
        return find_op() is not None
    return shutil.which("bw") is not None


def provider_is_installed(provider: "LoginBackendProvider") -> bool:
    """Registered plugin providers are present; stock providers require their CLI."""
    from agent.vault_backends.registry import list_providers

    if any(candidate is provider for candidate in list_providers()):
        return True
    return is_installed(provider.name)


def is_enabled(name: str) -> bool:
    """An installed manager is a login source unless the user opted out (``vault.<name>.enabled: false``).
    Zero-config on purpose: a user with ``bw``/``op`` on PATH should never have to discover a toggle."""
    section = _cfg().get(name) or {}
    if isinstance(section, dict) and section.get("enabled") is False:
        return False
    return is_installed(name)


def enabled_backends() -> List[LoginBackend]:
    """Local first (always on), then every detected external manager the user has not turned off."""
    from agent.vault_backends.local import LocalLoginBackend

    cfg = _cfg()
    out: List[LoginBackend] = [LocalLoginBackend()]
    for provider in available_backend_providers():
        section = cfg.get(provider.name) or {}
        if (
            not _replacement_is_active(provider)
            and isinstance(section, dict)
            and section.get("enabled") is False
        ):
            continue
        if not provider_is_installed(provider):
            continue
        backend = provider.create(
            section if isinstance(section, dict) else {}
        )
        if (
            backend.display_name != provider.display_name
            or backend.needs_unlock != provider.needs_unlock
        ):
            raise ValueError(
                f"login backend factory {provider.name!r} returned inconsistent public metadata"
            )
        out.append(backend)
    return out


def backend_for_handle(handle: str) -> Optional[LoginBackend]:
    return next((b for b in enabled_backends() if b.owns(handle)), None)
