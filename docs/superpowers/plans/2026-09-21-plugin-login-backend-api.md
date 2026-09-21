# Plugin Login Backend API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal, profile-scoped plugin API for browser credential-vault `LoginBackend` factories, including an explicit capability-gated path to replace a stock external backend.

**Architecture:** Add a focused vault-backend provider registry keyed by resolved Hermes home. Each registration stores public metadata plus a factory that receives only the backend's `vault.<name>` configuration mapping and creates a `LoginBackend`. `PluginContext` validates and leases each registration through the existing ownership ledger, while vault resolution overlays plugin providers on the unchanged local, 1Password, and Bitwarden defaults. Name and handle-prefix conflicts fail closed; `replace_stock=True` is allowed only for the matching stock external backend and only when the plugin has the `vault.login_backend_replace` capability.

**Tech Stack:** Python 3, `PluginManager`/`PluginContext`, profile-scoped registries, pytest through `scripts/run_tests.sh`, Ruff, Python compile checks.

**Spec:** This session's user requirements dated 2026-09-21; no separate spec file was requested.

## Global Constraints

- Do not change browser tool schemas, browser provider selection, browser fill semantics, or the browser toolset.
- Keep `LoginBackend`, `UnlockRequired`, metadata-only listing, server-side `resolve_password`, optional `resolve_otp`, and opaque handle routing unchanged.
- Preserve local, stock 1Password, and stock Bitwarden behavior when no plugin registers.
- Scope registrations to the owning `PluginManager` profile and remove them on unload or force reload.
- Reject duplicate backend names and duplicate handle prefixes deterministically; do not silently replace registrations.
- Permit stock replacement only through `replace_stock=True`, only for the matching stock backend name and prefix, and only with explicit `vault.login_backend_replace` consent.
- Do not put secret values in registration metadata, plugin configuration examples, logs, schemas, or errors.
- Use real plugin discovery tests with a temporary `HERMES_HOME`.
- Use `scripts/run_tests.sh`, never bare `pytest`.

---

### Task 1: Define the scoped login-backend registry contract

**Files:**
- Create: `agent/vault_backends/registry.py`
- Test: `tests/agent/test_vault_backend_registry.py`

**Interfaces:**
- Consumes: `agent.vault_backends.base.LoginBackend`; `hermes_constants.hermes_home_key()`.
- Produces:
  - `LoginBackendFactory = Callable[[Mapping[str, Any]], LoginBackend]`
  - `LoginBackendProvider(name, display_name, prefix, needs_unlock, factory, replaces_stock=False)`
  - `register_provider(provider, *, scope: str) -> None`
  - `list_providers(*, scope: str | None = None) -> list[LoginBackendProvider]`
  - `snapshot_registration(name, *, scope: str) -> LoginBackendProvider | None`
  - `restore_registration(name, current, previous, *, scope: str) -> bool`
  - `_reset_for_tests() -> None`

- [ ] **Step 1: Write failing registry tests**

```python
def test_registry_rejects_duplicate_name_and_prefix(profile_scope):
    first = LoginBackendProvider(
        name="broker", display_name="Broker", prefix="broker:",
        needs_unlock=True, factory=BrokerBackend,
    )
    register_provider(first, scope=profile_scope)

    with pytest.raises(ValueError, match="backend name 'broker' is already registered"):
        register_provider(replace(first, prefix="other:"), scope=profile_scope)
    with pytest.raises(ValueError, match="handle prefix 'broker:' is already registered"):
        register_provider(replace(first, name="other"), scope=profile_scope)


def test_registry_is_profile_scoped_and_restores_on_identity(profile_a, profile_b):
    provider = LoginBackendProvider(
        name="broker", display_name="Broker", prefix="broker:",
        needs_unlock=True, factory=BrokerBackend,
    )
    register_provider(provider, scope=profile_a)

    assert list_providers(scope=profile_a) == [provider]
    assert list_providers(scope=profile_b) == []
    assert restore_registration("broker", provider, None, scope=profile_a) is True
    assert list_providers(scope=profile_a) == []
```

- [ ] **Step 2: Run the registry tests and verify RED**

Run:

```bash
scripts/run_tests.sh tests/agent/test_vault_backend_registry.py
```

Expected: FAIL because `agent.vault_backends.registry` does not exist.

- [ ] **Step 3: Implement the minimal registry**

Create an immutable provider record. Validate non-empty lowercase backend names, non-empty prefixes, callable factories, and identity-safe restore. Keep one name map and one prefix index per explicit scope. Do not log factory arguments or constructed backend values.

```python
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
            raise ValueError(f"login backend factory {self.name!r} returned inconsistent public metadata")
        return backend
```

Registration must reject an existing name or prefix before mutating either index. Restore must remove or restore both indexes only when the current provider still owns the name slot.

- [ ] **Step 4: Run the registry tests and verify GREEN**

Run:

```bash
scripts/run_tests.sh tests/agent/test_vault_backend_registry.py
```

Expected: PASS.

- [ ] **Step 5: Commit the registry contract**

```bash
git add agent/vault_backends/registry.py tests/agent/test_vault_backend_registry.py
git commit -m "feat(vault): add scoped login backend registry

Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 2: Add the public PluginContext registration API

**Files:**
- Modify: `hermes_cli/plugin_capabilities.py`
- Modify: `hermes_cli/plugins.py`
- Test: `tests/hermes_cli/test_plugins_login_backend_registration.py`

**Interfaces:**
- Consumes: Task 1 `LoginBackendProvider` and registry snapshot/restore functions; existing `PluginContext._track`; existing `PluginContext.has_capability`.
- Produces:
  - `PluginContext.register_login_backend(factory, *, name: str, display_name: str, prefix: str, needs_unlock: bool = False, replace_stock: bool = False) -> PluginRegistration`
  - Capability id `vault.login_backend_replace`.

- [ ] **Step 1: Write failing real-discovery tests**

Create plugins under `$HERMES_HOME/plugins/<name>/` with `plugin.yaml` and `register(ctx)`. The valid plugin defines a `LoginBackend` subclass and calls:

```python
ctx.register_login_backend(
    BrokerBackend,
    name="broker",
    display_name="Broker vault",
    prefix="broker:",
    needs_unlock=True,
)
```

Tests must assert:

```python
manager = PluginManager()
manager.discover_and_load()

provider = login_backend_registry.snapshot_registration(
    "broker", scope=manager.scope_key
)
assert manager._plugins["broker-plugin"].enabled is True
assert provider is not None
assert provider.prefix == "broker:"
```

Add separate real-discovery tests for:

```python
assert "backend name 'broker' is already registered" in second_plugin.error
assert "handle prefix 'broker:' is already registered" in prefix_plugin.error
```

Add stock replacement tests:

```python
ctx.register_login_backend(
    BrokerBitwardenBackend,
    name="bitwarden",
    display_name="Broker Bitwarden",
    prefix="bw:",
    needs_unlock=True,
    replace_stock=True,
)
```

Without `vault.login_backend_replace`, loading must fail with an actionable permission error. With that capability granted in `plugins.entries.<id>.granted_capabilities`, discovery must register the replacement. A request to replace `local`, a non-stock name, or a stock name with a different prefix must fail.

- [ ] **Step 2: Run the plugin registration tests and verify RED**

Run:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py
```

Expected: FAIL because `PluginContext.register_login_backend` and the capability do not exist.

- [ ] **Step 3: Add the capability and registration method**

Add this capability row:

```python
(
    "vault.login_backend_replace",
    ("allow_login_backend_replace",),
    "Replace a stock external browser credential-vault backend while keeping host-owned vault tools and fill policy",
),
```

Implement an explicit method, not a generic provider-table row, because it must enforce name and prefix uniqueness plus stock replacement rules:

```python
def register_login_backend(
    self,
    factory: Callable[[Mapping[str, Any]], LoginBackend],
    *,
    name: str,
    display_name: str,
    prefix: str,
    needs_unlock: bool = False,
    replace_stock: bool = False,
) -> PluginRegistration:
    ...
```

Rules:

- Normalize `name` with `strip().lower()` and reject values outside `[a-z0-9][a-z0-9_-]{0,63}`.
- Reject empty `display_name`, empty `prefix`, non-callable factories, and prefixes used by local or stock backends.
- For `replace_stock=False`, reject all stock names and prefixes.
- For `replace_stock=True`, require `ctx.has_capability("vault.login_backend_replace")`, require `name` to be `onepassword` or `bitwarden`, and require the exact stock prefix.
- Create `LoginBackendProvider` and register it in `manager.scope_key`.
- Lease cleanup with `manager._track_scoped_registration(...)`.
- Keep logs to plugin id, backend name, prefix, and replacement state only.

- [ ] **Step 4: Run the plugin registration tests and verify GREEN**

Run:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py
```

Expected: PASS.

- [ ] **Step 5: Commit the public API**

```bash
git add hermes_cli/plugin_capabilities.py hermes_cli/plugins.py tests/hermes_cli/test_plugins_login_backend_registration.py
git commit -m "feat(plugins): register vault login backends

Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 3: Integrate plugin providers with vault resolution

**Files:**
- Modify: `agent/vault_backends/base.py`
- Modify: `agent/vault_backends/__init__.py`
- Modify: `hermes_cli/vault.py`
- Modify: `tui_gateway/methods_vault.py`
- Test: `tests/hermes_cli/test_plugins_login_backend_registration.py`
- Test: `tests/tools/test_browser_vault.py`

**Interfaces:**
- Consumes: Task 1 provider registry; Task 2 registration API.
- Produces:
  - `external_backend_providers() -> tuple[LoginBackendProvider, ...]`
  - Existing `enabled_backends() -> list[LoginBackend]`, now with profile-scoped plugin providers.
  - Existing `backend_for_handle(handle) -> LoginBackend | None`, unchanged to callers.

- [ ] **Step 1: Write failing end-to-end behavior tests**

Through real discovery, assert:

```python
backends = {backend.name: backend for backend in enabled_backends()}
assert set(backends) == {"local", "broker"}
assert backends["broker"].prefix == "broker:"
assert backend_for_handle("broker:item-1") is not None
assert backend_for_handle("broker:item-1").name == "broker"
```

Use a factory counter or recorded config mapping to prove the plugin factory receives only `vault.broker`, not the full config or any secret value:

```python
vault:
  broker:
    endpoint: https://broker.invalid
```

Add a two-profile A -> B -> A test. Each profile must discover its own plugin and see only its own provider. Unloading profile A must not remove profile B.

Add unload and force-reload assertions:

```python
manager.unload("broker-plugin")
assert "broker" not in {backend.name for backend in enabled_backends()}

manager.discover_and_load(force=True)
assert [backend.name for backend in enabled_backends()].count("broker") == 1
```

Add stock invariants with no plugin registration:

```python
with patch.object(base, "is_installed", return_value=True):
    assert [backend.name for backend in base.enabled_backends()] == [
        "local", "onepassword", "bitwarden"
    ]
```

For granted stock replacement, assert exactly one `bitwarden` backend exists, it is created by the plugin, `backend_for_handle("bw:item")` selects it, and core `browser_vault_*` tool registrations remain unchanged.

- [ ] **Step 2: Run focused integration tests and verify RED**

Run:

```bash
scripts/run_tests.sh \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py -k "login_backend or ManagerAutoDetection"
```

Expected: FAIL because vault resolution does not read plugin registrations.

- [ ] **Step 3: Overlay plugin providers on stock providers**

In `agent/vault_backends/base.py`:

- Define stock providers for 1Password and Bitwarden from their existing classes.
- Read plugin providers for the active `hermes_home_key()`.
- Keep stock order when there is no replacement.
- Replace a stock provider in place when a capability-approved provider has `replaces_stock=True`.
- Append non-stock plugin providers in deterministic `(name, prefix)` order.
- Instantiate enabled providers with only their own `vault.<name>` mapping.
- Continue to create `LocalLoginBackend()` first and route handles through `enabled_backends()`.

Update CLI and TUI source enumeration to use `external_backend_providers()` metadata rather than assuming every source is a class. Keep existing enable/disable configuration semantics.

- [ ] **Step 4: Run the focused integration tests and verify GREEN**

Run:

```bash
scripts/run_tests.sh \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py -k "login_backend or ManagerAutoDetection"
```

Expected: PASS.

- [ ] **Step 5: Commit vault integration**

```bash
git add \
  agent/vault_backends/base.py \
  agent/vault_backends/__init__.py \
  hermes_cli/vault.py \
  tui_gateway/methods_vault.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
git commit -m "feat(vault): load plugin login backends

Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 4: Document the plugin API and compatibility contract

**Files:**
- Modify: `website/docs/developer-guide/plugins/index.md`
- Modify: `website/docs/user-guide/features/credential-vault.md`

**Interfaces:**
- Consumes: Final Task 2 API signature and capability id.
- Produces: Exact author guidance for registration, replacement consent, lifecycle, configuration, and security boundaries.

- [ ] **Step 1: Add the developer API documentation**

Document this exact example:

```python
def register(ctx):
    ctx.register_login_backend(
        BrokerBackend,
        name="broker",
        display_name="Company credential broker",
        prefix="broker:",
        needs_unlock=True,
    )
```

Document the factory contract:

```python
class BrokerBackend(LoginBackend):
    def __init__(self, config: Mapping[str, Any]):
        ...
```

State that the factory receives only `vault.<name>`, must return a `LoginBackend` with the registered name and prefix, and must keep password/OTP resolution server-side. State that registration metadata is public and must never contain credentials.

Document deterministic conflicts, manager/profile scoping, unload cleanup, additive compatibility, and no implicit replacement.

Document stock replacement:

```yaml
capabilities:
  - vault.login_backend_replace
```

```python
ctx.register_login_backend(
    BrokerBitwardenBackend,
    name="bitwarden",
    display_name="Broker Bitwarden",
    prefix="bw:",
    needs_unlock=True,
    replace_stock=True,
)
```

Explain that consent is required, only stock 1Password or Bitwarden can be replaced, the prefix must stay exact, and core browser vault tools and fill policy remain host-owned.

- [ ] **Step 2: Update the credential-vault user guide**

Add a short source note: plugins can add login sources and, with explicit capability consent, replace a stock external source. Clarify that plugins do not change the browser tool schema, do not expose secret-listing tools, and cannot replace the local encrypted vault.

- [ ] **Step 3: Review documentation for secret leakage**

Run:

```bash
git --no-pager diff --check
git --no-pager diff -- website/docs/developer-guide/plugins/index.md website/docs/user-guide/features/credential-vault.md
```

Expected: no whitespace errors; examples contain only public metadata and placeholder endpoints.

- [ ] **Step 4: Commit documentation**

```bash
git add website/docs/developer-guide/plugins/index.md website/docs/user-guide/features/credential-vault.md
git commit -m "docs(plugins): document login backend API

Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

### Task 5: Validate, review, push, and open the upstream pull request

**Files:**
- Modify only if validation finds a defect tightly coupled to this change.

**Interfaces:**
- Consumes: All prior tasks.
- Produces: A verified branch and pull request against `NousResearch/hermes-agent:main`.

- [ ] **Step 1: Run focused tests**

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py \
  tests/tui_gateway/test_vault_methods.py
```

Expected: PASS.

- [ ] **Step 2: Run relevant plugin and vault suites**

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins.py tests/hermes_cli/test_plugins_*registration.py
scripts/run_tests.sh tests/agent/test_vault_backends.py tests/tools/test_browser_vault.py tests/tui_gateway/ -k vault
```

Expected: PASS.

- [ ] **Step 3: Run lint, compile, compatibility, and diff checks**

```bash
ruff check \
  agent/vault_backends \
  hermes_cli/plugins.py \
  hermes_cli/plugin_capabilities.py \
  hermes_cli/vault.py \
  tui_gateway/methods_vault.py \
  tests/agent/test_vault_backend_registry.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
python -m compileall -q agent/vault_backends hermes_cli tests/agent/test_vault_backend_registry.py tests/hermes_cli/test_plugins_login_backend_registration.py
python scripts/check_compat_pointers.py
git --no-pager diff --check
git --no-pager status --short
git --no-pager diff --stat main...HEAD
git --no-pager diff main...HEAD
```

Expected: all commands succeed; the diff contains only the plan, registry, plugin API, vault integration, tests, and related docs.

- [ ] **Step 4: Review the completed changes**

Use the repository review workflow to check standards and the user requirements. Fix all high-confidence findings, then rerun the smallest affected test command and `git diff --check`.

- [ ] **Step 5: Commit any final fixes**

```bash
git add <only-files-changed-by-final-fixes>
git commit -m "fix(vault): harden plugin backend registration

Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
```

Skip this commit when review finds no changes.

- [ ] **Step 6: Push the branch**

```bash
git push -u origin HEAD
```

Expected: the fork branch is available on `KalebCole/hermes-agent`.

- [ ] **Step 7: Open the pull request**

```bash
gh pr create \
  --repo NousResearch/hermes-agent \
  --base main \
  --head KalebCole:kalebcole-plugin-login-backend-api \
  --title "feat(vault): add plugin login backend API" \
  --body-file <generated-pr-body-file>
```

The PR body must state the API signature, fail-closed replacement contract, test commands, and non-goals. If direct upstream creation is rejected by permissions, create the same head-to-base PR through the normal fork flow and report the exact URL and error context.

### Task 6: Add native unlock and transactional replacement activation

**Files:**
- Modify: `agent/vault_backends/base.py`
- Modify: `agent/vault_backends/registry.py`
- Modify: `hermes_cli/plugins.py`
- Modify: `tools/browser_vault_tool.py`
- Modify: `tests/hermes_cli/test_plugins_login_backend_registration.py`
- Modify: `website/docs/developer-guide/plugins/index.md`

**Interfaces:**
- Consumes: The scoped login-backend provider registry and `PluginContext.register_login_backend`.
- Produces:
  - `LoginBackend.unlock_noninteractive() -> bool`
  - `PluginContext.set_login_backend_active(name: str, active: bool) -> None`
  - Generic list, unlock, fill, and rejected-session refresh behavior for native/passwordless backends.

- [ ] **Step 1: Write failing real-discovery integration tests**

Create a real plugin backend with `needs_unlock = True` that implements:

```python
def unlock_noninteractive(self) -> bool:
    self.session_valid = True
    return True
```

Through `PluginManager.discover_and_load()`, assert:

- `browser_vault_list()` calls native unlock and returns metadata without a prompt.
- `browser_vault_unlock("broker")` succeeds in a headless session without a prompt or secret argument.
- `browser_vault_fill()` retries once after `get_meta()` or `resolve_password()` raises `UnlockRequired` for a rejected session, refreshes through `unlock_noninteractive()`, and fills without prompt data in tool input or output.
- Stock Bitwarden still uses its existing interactive unlock behavior.

- [ ] **Step 2: Run the native-unlock tests and verify RED**

Run:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py -k noninteractive
```

Expected: FAIL because `LoginBackend.unlock_noninteractive()` and the generic tool flow do not exist.

- [ ] **Step 3: Add the default native-unlock method and generic tool flow**

Add this backward-compatible default:

```python
def unlock_noninteractive(self) -> bool:
    """Try a backend-owned unlock or session refresh without user secret input."""
    return False
```

Before reporting a backend as locked or prompting, `browser_vault_list()`, `browser_vault_unlock()`, and `browser_vault_fill()` must call this method. If `get_meta()` or secret resolution raises `UnlockRequired`, call the method and retry the rejected operation once. Never pass a password, OTP, or other secret into the method. Keep the browser tool schemas unchanged.

- [ ] **Step 4: Write failing transactional activation tests**

Through real discovery of a capability-approved stock Bitwarden replacement, assert:

```python
ctx.set_login_backend_active("bitwarden", True)
```

atomically persists:

```yaml
plugins:
  entries:
    broker-plugin:
      settings:
        login_backends:
          bitwarden:
            enabled: true
            prior_stock:
              present: true
              value: true
vault:
  bitwarden:
    enabled: false
```

Use the per-backend state path
`plugins.entries.<plugin_id>.settings.login_backends.<backend_name>`, with
`enabled: bool` and `prior_stock: {present: bool, value?: Any}`. Assert the
first activation snapshots the raw stock key, enables only that replacement,
and disables the stock backend in one atomic write. Cover prior stock values
`true`, `false`, and absent. Repeated activation must be a no-op that does not
replace the snapshot.
Deactivation must restore the exact raw value or exact absence and consume a
valid snapshot in the same write; without a valid snapshot it must not touch the
stock key. Repeated deactivation must be a no-op that never overwrites a later
user change. Assert unrelated raw config survives. Assert a managed install,
any of the three exact managed paths (active, rollback, or stock), malformed
config, or a save exception raises and leaves the file unchanged. Assert a
plugin cannot activate a backend registration it does not own or a
non-replacement backend.

- [ ] **Step 5: Implement the narrow activation API**

Add:

```python
def set_login_backend_active(self, name: str, active: bool) -> None:
    ...
```

The method may target only this plugin's active `replace_stock=True`
registration. It validates the active, dynamic rollback, and stock dotted paths
through managed-scope rules, holds `_locked_plugin_state(config_path)` and
`_CONFIG_LOCK` across a fail-closed raw read plus one atomic config write, and
never catches write exceptions. It may mutate the raw mapping and call
`save_config(..., strip_defaults=False)` so exact stock-key absence can be
restored. The provider record carries the owning plugin id so vault resolution
can select the replacement only when the raw owner setting
`settings.login_backends.<backend_name>.enabled` is exactly `true`. Missing,
false, malformed, or unreadable settings leave it inactive, and plugin manifest
defaults are not consulted. When active, `vault.<stock>.enabled` applies to the
stock backend and does not suppress the replacement. Targeted unload restores
owned active replacements; force reload carries them through discovery and
restores only omitted, disabled, or failed registrations. Routine unload-all
does not mutate config.

- [ ] **Step 6: Run the focused tests and verify GREEN**

Run:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py tests/tools/test_browser_vault.py
```

Expected: PASS.

- [ ] **Step 7: Document and validate the final APIs**

Document `unlock_noninteractive()` and `set_login_backend_active()` with their no-secret, managed-scope, atomic-write, rollback, and ownership rules. Then run:

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
ruff check agent/vault_backends hermes_cli/plugins.py tools/browser_vault_tool.py tests/hermes_cli/test_plugins_login_backend_registration.py
python -m compileall -q agent/vault_backends hermes_cli/plugins.py tools/browser_vault_tool.py
python scripts/check_compat_pointers.py
git --no-pager diff --check
```

Expected: all commands pass.
