# Runtime profiles

The core spec ([`../../SPEC.md`](../../SPEC.md)) is runtime-neutral. Everything a
particular runtime needs — its `runtime` id, extra `delivery` methods, the
`<runtime>:` namespaced filesystem scopes and `AXP_<RUNTIME>_*` env variables
it provides, how it realises each `component_map` entry, and which enforcement
tier it can honestly offer — lives in one profile document here.

**Adding a runtime = adding a profile document.** The core does not change.

| runtime id    | profile                              | status                              |
|---------------|--------------------------------------|-------------------------------------|
| `posix`       | [posix.md](posix.md)                 | normative baseline (part of core)   |
| `hermes`      | [hermes.md](hermes.md)               | implemented (mintbot host)          |
| `openclaw`    | [openclaw.md](openclaw.md)           | draft                               |
| `claude-code` | [claude-code.md](claude-code.md)     | draft                               |

Unregistered runtimes use reverse-DNS ids (`com.example.myagent`). To register
a short id, open a pull request adding `<id>.md` and a row above. Ids are
lowercase `[a-z][a-z0-9-]*`; once registered they are never reassigned.

A profile MUST state:

1. **Runtime id** and how `runtime_version` is determined on the host.
2. **Delivery methods** beyond `archive` (if any) and their trust root.
3. **Scopes** — the `<runtime>:<scope>` filesystem scopes it understands and
   the real paths they map to.
4. **Environment** — extra `AXP_<RUNTIME>_*` variables handed to lifecycle hooks.
5. **Component realisation** — what the host does with each `component_map`
   entry it understands (string and rich form).
6. **Enforcement** — the highest tier the runtime can honestly apply, and what
   exactly is and is not contained at each tier.
