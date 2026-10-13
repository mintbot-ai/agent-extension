# AXP conformance suite

Executable checks for the host conformance profiles in SPEC §11. A host
claiming a profile SHOULD pass the corresponding module:

| profile   | module            | what it checks                                            |
|-----------|-------------------|-----------------------------------------------------------|
| Core      | `test_core.py`    | manifest acceptance/refusal semantics (§2.4 forward-compat, closed security enums), target selection incl. the `posix` fallback (§5) |
| Panel declarations (0.5) | `test_panel_views.py` | safe service references, loopback origins and paths, unknown capabilities, optional activation hooks |
| Trusted   | `test_trusted.py` | TOFU pinning, same-key rule, announce → dual-sign rotation, the signed→unsigned ratchet (§8) |

(Managed and Sandboxed profiles involve network and systemd side effects and
are exercised by host-specific integration tests, not here.)

`test_panel_views.py` targets validators that understand the 0.5 panel component.
Older hosts may ignore this component under §2.4 and should run the Core/Trusted
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
