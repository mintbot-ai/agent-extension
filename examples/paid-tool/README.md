# Commerce example: a sold extension with a gated artifact (AXP 0.5, SPEC §14)

`ext.example.com/paid-tool` is a fictional sold extension. The manifest is
public and signed as always — discovery, the consent card and update checks
need it — but the artifact is released **only against an entitlement**
(`targets[].delivery.auth.scheme: entitlement`): a host without one never
receives the code. Three plans are offered: a monthly subscription, a
lifetime licence with twelve months of updates, and a 14-day trial.

Everything here is a structural fixture, not a published release: the
all-zero digests, the script paths and the example domain are placeholders;
no installer or daemon is shipped.

| file | what it is |
|------|------------|
| `agent-extension.json` | the signed manifest with a `commerce` block and a gated `posix` target |
| `agent-extension-keys.json` | the publisher's key directory: the manifest key (no `roles`) and the **online issuing key** (`roles: ["entitlement"]`), both scoped to `paid-tool` |
| `entitlement.json` | a `lifetime` entitlement issued to the example host, updates covered until 2027-10-16 |
| `example-issuing.key` | the issuing key's private half — **deliberately public**, trusted by nothing |
| `example-host.key` | the example host's key — the entitlement's `holder` is its public form; equally public |

The manifest is signed with `../sample-memory/example-signing.key`, the
repository's shared, public example key.

## Walk the whole flow

```bash
axp validate examples/paid-tool/agent-extension.json
axp verify examples/paid-tool/agent-extension.json --keydir examples/paid-tool/agent-extension-keys.json

# the host checks the entitlement it holds (SPEC 14.3); a real host passes --holder <its own key>
axp entitlement verify examples/paid-tool/entitlement.json \
    --manifest examples/paid-tool/agent-extension.json \
    --keydir examples/paid-tool/agent-extension-keys.json

# the header the host sends to fetch the gated artifact (SPEC 14.4)
axp entitlement present examples/paid-tool/entitlement.json \
    --host-key examples/paid-tool/example-host.key \
    --audience https://ext.example.com/paid-tool-1.0.0.tar.gz --value-only > /tmp/token

# what the artifact server does with it
axp entitlement inspect @/tmp/token --audience https://ext.example.com/paid-tool-1.0.0.tar.gz \
    --manifest examples/paid-tool/agent-extension.json \
    --keydir examples/paid-tool/agent-extension-keys.json

# the issuer side: a new entitlement for another host
axp entitlement issue --key examples/paid-tool/example-issuing.key --issuer ext.example.com \
    --extension ext.example.com/paid-tool --holder ed25519:… --plan pro-monthly --valid-days 30
```

The manifest key cannot vouch for an entitlement and the issuing key cannot
sign a manifest: `axp.signing.parse_key_directory(..., role=…)` returns each
for its role only. That separation is the point of `roles` — the issuing key
lives on a server that signs on every purchase, the manifest key stays offline.
