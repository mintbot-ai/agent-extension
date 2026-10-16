# AXP conformance suite

Executable checks for the host conformance profiles in SPEC §11. A host
claiming a profile SHOULD pass the corresponding module:

| profile   | module            | what it checks                                            |
|-----------|-------------------|-----------------------------------------------------------|
| Core      | `test_core.py`    | manifest acceptance/refusal semantics (§2.4 forward-compat, closed security enums), target selection incl. the `posix` fallback (§5) |
| Panel declarations (0.5) | `test_panel_views.py` | safe service references, loopback origins and paths, unknown capabilities, optional activation hooks |
| Trusted   | `test_trusted.py` | TOFU pinning, same-key rule, announce → dual-sign rotation, the signed→unsigned ratchet (§8) |
| Commerce (optional capability) | `test_commerce.py` | entitlement verification as a host runs it (§14): holder and extension binding, issuer and key-role trust, grace and expiry, tamper refusal; the issuing key cannot move a pin; `updates_until` coverage |

(Managed and Sandboxed profiles involve network and systemd side effects and
are exercised by host-specific integration tests, not here. Likewise the
commerce module checks the decision, not the checkout, refresh or gated
fetch — those are HTTP and belong to a host's integration tests.)

`test_commerce.py` runs only for adapters that implement the optional
`verify_entitlement` method (see `adapter.py`); a host that does not sell
extensions skips it without claiming anything.

`test_key_directory.py` uses the optional `parse_key_directory` adapter method
to test raw constraints, including malformed scope/roles and unfiltered
(`name=None`) lookups. It never prefilters the host's input through the
reference parser. Commerce cases also cover malformed issuer constraints and
manifest grace policies of zero and more than seven days.

`test_panel_views.py` targets validators that understand the 0.5 panel component.
Older hosts may ignore this component under §2.4 only if the manifest does not
also declare unsupported lifecycle hooks: pre-0.5 reference validators/schemas
reject `enable`/`disable`. Upgrade to 0.5 for activation hooks; lifecycle keys
remain a closed vocabulary. Older hosts should run the Core/Trusted
modules without claiming 0.5 panel validation. Passing declaration tests does
not certify browser isolation or proxy security: run the host integration
acceptance checklist in `docs/HOST-GUIDE.md`, including credential stripping,
scoped capability expiry and closing already-open WebSockets on disable.
Unsupported hosts must never expose a view or raw service link.

## Running against the reference implementation

```bash
pip install -e .[dev]
pytest conformance/
```

## Running against YOUR host

Implement the three-method adapter from `adapter.py` for your host and point
the suite at it:

```bash
AXP_CONFORMANCE_ADAPTER=my_host.axp_adapter pytest conformance/
```

The module must expose `make_adapter() -> Adapter`. Each test gets a fresh
adapter, so trust state never leaks between cases.
