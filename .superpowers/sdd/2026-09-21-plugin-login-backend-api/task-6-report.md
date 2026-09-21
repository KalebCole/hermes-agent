# Task 6 Report — Native unlock and transactional replacement activation

## Status

Complete. Commit: `7bc349a85a` (`feat(vault): add native plugin unlock activation`).

## TDD evidence

### Native unlock RED

Command:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py -k noninteractive
```

Observed five failures before implementation. The focused API proof failed with:

```text
AttributeError: 'BitwardenLoginBackend' object has no attribute 'unlock_noninteractive'
```

### Native unlock GREEN

The same command passed:

```text
5 tests passed, 0 failed
```

### Replacement activation RED

Command:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k 'replacement_activation or cannot_activate' --tb=short
```

Observed eight failures before implementation. The focused transaction proof failed with:

```text
AttributeError: 'PluginContext' object has no attribute 'set_login_backend_active'
```

The replacement-selection contract was separately proven RED after removing the
selection implementation:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k replacement_selection --tb=short
```

It failed because an active replacement was suppressed by
`vault.bitwarden.enabled: false` (`StopIteration` while selecting Bitwarden).

### Replacement activation GREEN

Focused activation tests passed:

```text
8 tests passed, 0 failed
```

Replacement selection passed:

```text
1 test passed, 0 failed
```

The requested focused pair passed:

```bash
scripts/run_tests.sh \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
```

```text
89 tests passed, 0 failed
```

## Files changed

- `agent/vault_backends/base.py`
- `agent/vault_backends/registry.py`
- `hermes_cli/plugins.py`
- `tools/browser_vault_tool.py`
- `tests/hermes_cli/test_plugins_login_backend_registration.py`
- `website/docs/developer-guide/plugins/index.md`

The pre-existing modification to
`docs/superpowers/plans/2026-09-21-plugin-login-backend-api.md` was not included
in the Task 6 commit.

## Final public signatures

```python
class LoginBackend:
    def unlock_noninteractive(self) -> bool:
        """Try a backend-owned unlock or session refresh without user secret input."""
        return False
```

```python
class PluginContext:
    def set_login_backend_active(self, name: str, active: bool) -> None:
        ...
```

`LoginBackendProvider` now carries:

```python
owner_plugin_id: str | None = None
```

## Call-path behavior

- `browser_vault_list()` tries `unlock_noninteractive()` before reporting a
  backend as locked. A successful backend-owned refresh allows metadata listing
  without a prompt.
- `browser_vault_unlock()` tries the no-argument native method before checking
  interactive prompt availability. Returning `False` preserves the existing
  stock 1Password/Bitwarden prompt flow.
- `browser_vault_fill()` uses the same unlock path before filling a backend that
  reports itself locked.
- If `get_meta()`, `resolve_password()`, or `resolve_secret()` rejects a stale
  session with `UnlockRequired`, Hermes calls `unlock_noninteractive()` once and
  retries only that rejected operation once. A second rejection returns the
  existing `unlock_required` response.
- The native method receives no password, OTP, token, or other secret. Browser
  tool schemas and fill result shapes remain unchanged, and tests assert that
  the plugin password is absent from tool output.
- Stock Bitwarden inherits the default `False` implementation and therefore
  keeps its interactive master-password behavior.

## Replacement selection and config transaction

- Registration records the owner plugin id.
- A stock replacement is selected unless
  `plugins.entries.<owner>.settings.login_backend_enabled` is explicitly
  `false`.
- While selected, `vault.<stock_name>.enabled: false` applies only to the stock
  provider and does not suppress the replacement.
- `set_login_backend_active()` accepts only the calling plugin's current
  `replace_stock=True` registration.
- Activation performs one merge save writing:

  ```yaml
  plugins:
    entries:
      <plugin_id>:
        settings:
          login_backend_enabled: true
  vault:
    <stock_name>:
      enabled: false
  ```

- Deactivation writes the inverse booleans.
- The operation holds `_locked_plugin_state(config_path)` and `_CONFIG_LOCK`
  across managed-policy validation, a fail-closed raw config read, and one
  `save_config(..., merge_existing=True)` call.
- It rejects a managed install and validates both exact managed dotted paths:
  `plugins.entries.<plugin_id>.settings.login_backend_enabled` and
  `vault.<stock_name>.enabled`.
- Malformed YAML and save exceptions propagate. Integration tests verify the
  file remains byte-for-byte unchanged on every rejected/error path and that
  unrelated keys survive successful writes.

## Final verification

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
```

Result: `103 tests passed, 0 failed`.

```bash
.venv/bin/ruff check agent/vault_backends hermes_cli/plugins.py \
  tools/browser_vault_tool.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
```

Result: `All checks passed!`

```bash
.venv/bin/python -m compileall -q \
  agent/vault_backends hermes_cli/plugins.py tools/browser_vault_tool.py
.venv/bin/python scripts/check_compat_pointers.py
git --no-pager diff --check
```

Results: all exited zero; compatibility check reported no in-tree dependency on
plugin-compat pointers.

## Self-review

- Reviewed the complete Task 6 diff for reuse, quality, efficiency, ownership,
  secret handling, schema stability, and one-retry behavior.
- Reused existing plugin/config locks, managed-scope checks, raw-read guard,
  merge-save path, provider registry, and browser unlock flow.
- No new tool schema, secret-bearing parameter, broad fallback, compatibility
  shim, or unrelated refactor was introduced.

## Concerns

None. The shell does not expose a bare `python` or `ruff` executable, so the
equivalent project-venv executables were used for the required compile,
compatibility, and lint commands.

## Review round 1 fix

Fixed the replacement activation transaction so it preserves the stock
backend's raw pre-activation state instead of writing inverse booleans.

---

# Task 7 Report — Durable host-owned revocation generation

## Status

Complete in commit `fix(vault): add durable plugin revocation generations`
(this commit).

## TDD evidence

The first focused RED run covered real CLI/dashboard command paths:

```bash
scripts/run_tests.sh \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/hermes_cli/test_plugins_cmd_login_backend_cleanup.py \
  -k 'revokes_loaded or reenable_force or reinstall_new or rechecks_capability or generation_is_profile or already_disabled or malformed_generation or managed_generation' \
  --tb=short
```

The cleanup file produced five expected failures: the generation key was
missing, malformed generations did not abort, and a managed generation did not
block disable. The registration tests also demonstrated that stale loaded
contexts could reactivate after disable/remove.

During review, a separate profile-scope RED test proved that a profile-A
context could mutate profile B before the explicit scope fence:

```text
Failed: DID NOT RAISE PermissionError
```

After implementation, the focused pair passed:

```text
163 tests passed, 0 failed
```

## Contract implemented

- Hermes owns
  `plugins.entries.<plugin_id>.login_backend_generation`; it is outside
  plugin-controlled `settings`.
- Missing means generation zero. Bool, non-integer, negative, malformed-parent,
  and unreadable values fail closed.
- Every `LoginBackendProvider` captures its profile generation during real
  registration.
- CLI/dashboard disable restores leases, increments generation, and moves the
  enabled/disabled lists in one locked config transaction.
- CLI/dashboard remove restores leases and increments generation before the
  plugin tree is deleted.
- An already-disabled plugin with a stranded active lease is repaired and
  incremented once; repeating the command does not rewrite or increment.
- Activation verifies exact provider identity, owning profile, generation,
  canonical manifest eligibility, user/project package plus manifest
  existence, and the live replacement capability before any config mutation.
- Re-enable/reinstall requires new discovery. The new provider can activate;
  the old context remains rejected.
- Generation and lease paths participate in managed-config validation.

## Verification

Focused vault/plugin and command/manager suites:

```text
355 tests passed, 0 failed
```

Broader plugin registration/ownership/API compatibility suites:

```text
43 tests passed, 0 failed
```

Ruff, compileall, compatibility-pointer validation, and `git diff --check`
all exited zero.

## Concerns

None.

- The dynamic rollback key is
  `plugins.entries.<plugin_id>.settings.prior_stock_<backend_name>`.
- First activation snapshots the stock key as `{present: bool, value?: Any}`,
  enables the replacement, and disables the stock backend in one locked atomic
  full-config write.
- Repeated activation and repeated deactivation are byte-for-byte no-ops.
- Deactivation restores the exact prior raw value or exact absence and consumes
  a valid snapshot. Without a valid snapshot, it leaves the stock key untouched.
- Managed-scope validation now covers the active, rollback, and stock paths.
- Documentation and the tracked Task 6 plan now describe rollback rather than
  inverse-value behavior.

### TDD evidence

RED:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k 'replacement_activation or replacement_deactivation' --tb=short
```

Result before implementation: `5 passed, 7 failed`. The failures showed missing
rollback snapshots, incorrect restoration, and non-idempotent repeated calls.

GREEN:

```text
12 tests passed, 0 failed
```

### Review-round verification

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
```

Result: `109 tests passed, 0 failed`.

```bash
.venv/bin/ruff check agent/vault_backends hermes_cli/plugins.py \
  tools/browser_vault_tool.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python -m compileall -q \
  agent/vault_backends hermes_cli/plugins.py tools/browser_vault_tool.py
.venv/bin/python scripts/check_compat_pointers.py
git --no-pager diff --check
```

Results: all passed; compatibility check found no in-tree dependency on plugin
compatibility pointers.

## Review round 2 fix

Replacement selection now requires explicit activation from the raw owner
setting. A capability-approved registered stock replacement remains inactive
unless
`plugins.entries.<owner>.settings.login_backend_enabled` is exactly `true`.
Missing, false, malformed, or unreadable values retain stock behavior, and
plugin manifest defaults are not consulted. The rollback transaction from
`cd17f4202d` is unchanged.

The prior stock-slot test now activates the replacement before asserting its
routing behavior. The developer documentation, tracked plan, and Task 6 brief
now describe explicit activation.

### TDD evidence

RED:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k replacement_selection_requires_explicit_owner_activation --tb=short
```

Result before implementation: `1 failed`. The discovered replacement was
selected immediately, producing `Broker Bitwarden` where stock `Bitwarden` was
expected.

GREEN:

```text
1 test passed, 0 failed
```

### Review-round verification

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
```

Result: `109 tests passed, 0 failed`.

```bash
.venv/bin/ruff check agent/vault_backends hermes_cli/plugins.py \
  tools/browser_vault_tool.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python -m compileall -q \
  agent/vault_backends hermes_cli/plugins.py tools/browser_vault_tool.py
.venv/bin/python scripts/check_compat_pointers.py
git --no-pager diff --check
```

Results: all passed; compatibility check found no in-tree dependency on plugin
compatibility pointers.

## Final whole-branch review fix

`PluginContext.set_login_backend_active()` now fails closed before mutation when
the config root or any relevant parent under `plugins.entries.<plugin_id>.settings`
or `vault.<backend>` is present but is not a mapping. Missing relevant parents
are still created, while malformed unrelated sections remain untouched and do
not block activation.

Present activation and rollback records are also validated before the no-op
check or any mutation:

- `login_backend_enabled` must be a bool.
- `prior_stock_<backend>` must be a mapping with a bool `present`.
- A present stock value requires exactly `present` plus `value`; an absent stock
  value requires exactly `present`.

Parameterized activation and deactivation tests cover malformed roots, relevant
parents, activation values, and rollback records. Every rejected case asserts a
clear `TypeError` or `ValueError`, no `save_config()` call, and byte-for-byte
config preservation. A positive test preserves an unrelated malformed section.

### TDD evidence

RED:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k 'malformed_relevant_parent or malformed_active_value or malformed_snapshot or unrelated_malformed_section' \
  --tb=short
```

Result before implementation: `1 passed, 34 failed`. The setter replaced or
silently accepted malformed relevant structures and records.

GREEN:

```text
35 tests passed, 0 failed
```

### Final-fix verification

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
```

Result: `146 tests passed, 0 failed`.

```bash
.venv/bin/ruff check hermes_cli/plugins.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python -m compileall -q \
  hermes_cli/plugins.py tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python scripts/check_compat_pointers.py
git --no-pager diff --check
```

Results: all passed; compatibility check found no in-tree dependency on plugin
compatibility pointers.

### Final-fix concerns

None.

## Final-review lifecycle blocker fix

Status: complete.

### Exact persisted activation contract

Stock replacements are independently controlled under:

```yaml
plugins:
  entries:
    <plugin_id>:
      settings:
        login_backends:
          <backend_name>:
            enabled: true
            prior_stock:
              present: true
              value: <exact prior raw value>
```

`prior_stock` is exactly `{present: bool, value?: Any}`. A replacement is
selected only when its own backend entry has `enabled is True`; another
replacement registered by the same plugin is unaffected. Activation snapshots
and disables only `vault.<backend_name>.enabled`. Deactivation restores the
exact prior value or absence, consumes `prior_stock`, and leaves the backend
entry with `enabled: false`. Existing malformed-structure rejection,
managed-path checks, atomic locking/write behavior, idempotency, and no-secret
constraints remain enforced.

### Exact unload and reload lifecycle contract

- Targeted unload/disable/uninstall captures only current, identity-owned,
  active stock replacements, restores their saved stock settings, and consumes
  rollback state before disposing their registrations.
- Routine unload-all/process shutdown does not mutate configuration.
- Force rediscovery explicitly parks active login-backend carryovers during
  unload-all. After discovery, a replacement from the same plugin/backend that
  successfully re-registers with the same active state and snapshot is
  preserved without a transient restore.
- Omitted, disabled, or failed replacements are restored after the discovery
  attempt. The same reconciliation runs when discovery raises.
- Reconciliation requires the captured scope, current provider ownership,
  exact backend name, exact `enabled: true` state, and unchanged rollback
  snapshot. Consumed or user-modified state is not replayed, so stale cleanup
  cannot overwrite a later generation.
- All config reads/writes execute under the manager's profile home scope.
  Targeted unload in profile A leaves profile B's config and registration
  unchanged.

The implementation keeps the transaction and reconciliation logic in
`hermes_cli/plugins_login_backend.py`; `PluginManager` owns carryover records
and passes explicit force-rediscovery intent into `_unload_scoped()`.

### TDD evidence

RED command:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k 'dual_replacement or targeted_unload_restores or routine_unload_all or force_reload_omitting or failed_force_reload or successful_force_reload or repeated_cleanup or targeted_unload_isolated' \
  --tb=short
```

Observed before implementation: `5 failed, 3 passed`. Failures proved the
plugin-wide config shape, missing targeted cleanup, missing omitted/failed
reload cleanup, and missing profile-scoped restoration.

GREEN focused lifecycle result after implementation: `9 passed, 0 failed`
(including discovery-exception cleanup).

### Final verification evidence

Four-file vault suite:

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backend_registry.py \
  tests/agent/test_vault_backends.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/tools/test_browser_vault.py
```

Result: `159 passed, 0 failed`.

Relevant plugin-manager suites:

```bash
scripts/run_tests.sh \
  tests/hermes_cli/test_plugin_ownership_ledger.py \
  tests/hermes_cli/test_plugins.py \
  --tb=short
```

Result: `113 passed, 0 failed`.

Other plugin registration suites:

```bash
scripts/run_tests.sh \
  tests/hermes_cli/test_plugins_tts_registration.py \
  tests/hermes_cli/test_plugins_transcription_registration.py
```

Result: `6 passed, 0 failed`.

Static verification:

```bash
.venv/bin/ruff check \
  agent/vault_backends/base.py \
  hermes_cli/plugins.py \
  hermes_cli/plugins_ledger.py \
  hermes_cli/plugins_login_backend.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python -m compileall -q \
  agent/vault_backends \
  hermes_cli/plugins.py \
  hermes_cli/plugins_ledger.py \
  hermes_cli/plugins_login_backend.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python scripts/check_compat_pointers.py
git --no-pager diff --check
```

All exited zero. Compatibility validation reported no in-tree dependency on
the 2087 plugin-compat pointers.

Final combined verification ran all eight listed test files in one invocation:
`278 passed, 0 failed`.

### Concerns

None.

## Remaining Important finding — carryover parent validation

`capture_carryovers()` now reuses the strict activation parent-mapping
validation before reading each current candidate's active and rollback values.
Targeted unload and force rediscovery therefore raise before disposal when a
relevant `plugins`, `entries`, plugin entry, `settings`, `login_backends`, or
backend-state container is malformed. Routine non-force unload-all remains
config-blind and non-mutating.

### TDD evidence

RED:

```bash
scripts/run_tests.sh tests/hermes_cli/test_plugins_login_backend_registration.py \
  -k 'validate_replacement_parent_mappings' --tb=short
```

Result before implementation: all 12 targeted/force cases failed with
`Failed: DID NOT RAISE TypeError`.

GREEN:

```text
12 tests passed, 0 failed
```

Every parameterized case also asserts the registration remains live and config
bytes remain unchanged.

### Verification evidence

- Focused login-backend suites: `123 passed, 0 failed`.
- Relevant plugin/vault suites: `153 passed, 0 failed`.
- Ruff: all checks passed.
- `compileall`: exited zero.
- Compatibility validation: no in-tree dependency on 2,087 pointers.
- `git diff --check`: exited zero.

### Concerns

None.

## Final-review blocker follow-up

Implemented the remaining lifecycle blockers:

- CLI and dashboard disable/remove restore persisted active stock-backend
  replacement leases before changing plugin state or deleting files.
- Targeted unload and force rediscovery now fail closed on unreadable or
  malformed activation state before registration disposal; routine unload-all
  does not read activation config.
- Force reload can hand an active replacement from owner A to an explicitly
  active owner B without briefly restoring stock, while preserving A's
  original exact stock snapshot for B's later deactivation.

### TDD evidence

The new command/dashboard cleanup tests were run before implementation and
failed as expected: `10 failed, 0 passed`. The failures showed leases remaining
active, malformed state not aborting disable/remove, and unreadable state
reaching the old mutation path. Targeted/force unload and different-owner
handoff tests likewise failed against the previous lifecycle behavior.

After implementation, the final focused verification was:

```bash
scripts/run_tests.sh \
  tests/agent/test_vault_backends.py \
  tests/agent/test_vault_backend_registry.py \
  tests/hermes_cli/test_plugins.py \
  tests/hermes_cli/test_plugins_cmd.py \
  tests/hermes_cli/test_plugins_cmd_enable_disable_nested.py \
  tests/hermes_cli/test_plugins_cmd_login_backend_cleanup.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py \
  tests/hermes_cli/test_plugins_tts_registration.py \
  tests/hermes_cli/test_plugins_transcription_registration.py \
  -q --tb=short
```

Result: `279 passed, 0 failed`.

Static verification:

```bash
.venv/bin/ruff check \
  hermes_cli/plugins_login_backend.py \
  hermes_cli/plugins_ledger.py \
  hermes_cli/plugins_cmd.py \
  tests/hermes_cli/test_plugins_cmd_login_backend_cleanup.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python -m compileall -q \
  hermes_cli/plugins_login_backend.py \
  hermes_cli/plugins_ledger.py \
  hermes_cli/plugins_cmd.py \
  tests/hermes_cli/test_plugins_cmd_login_backend_cleanup.py \
  tests/hermes_cli/test_plugins_login_backend_registration.py
.venv/bin/python scripts/check_compat_pointers.py
git --no-pager diff --check
```

All exited zero. Compatibility validation again reported no in-tree dependency
on the 2087 plugin-compat pointers.

### Concerns

None.
