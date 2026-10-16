# Protocol review: security constraints and lifecycle outcomes

This review separates implemented corrections from proposals. It does not add
new manifest fields or lifecycle hooks, change the spec version, or promise
transactional rollback by arbitrary publisher scripts.

## Corrections implemented

- Key-directory constraints fail closed. An absent `extensions` field remains
  unrestricted; a present malformed value does not. An absent `roles` field is
  manifest-only; explicit null is not absence. Mixed malformed list entries
  invalidate the key entry rather than widening its authority.
- Role-aware readers do not accept an entitlement-only key for manifest first
  use, rotation or recovery when checking a key directory. Pre-role readers
  cannot enforce this restriction; adding the field or bumping a manifest
  version does not retrofit it. SPEC sections 2.4, 13 and 14.3 say so explicitly.
- CLI entitlement verification and presentation inspection resolve grace from
  an explicit CLI override, then the manifest, then the default. Zero remains
  meaningful and malformed local policy is rejected.
- The OpenSSL backend validates the exact Ed25519 SubjectPublicKeyInfo shape
  instead of treating any final 32 DER bytes as an Ed25519 public key. Backend
  equivalence tests cover X25519, Ed448, RSA, EC and malformed DER.

## Proposed next changes — not implemented

### 1. Define failure outcomes, not a universal rollback mechanism

Section 6.4 defines nonzero exit as failure but does not distinguish failure
before mutation, restored prior state, and unknown/partial mutation. Retrying an
idempotent hook is useful; it is not evidence that the previous version is intact.

Specify the observable host obligations: preserve last-known metadata and
recovery artifacts until the new installation is committed, do not advance trust
on failed finalization, revoke access to an unverified partial installation, and
report uncertainty rather than a successful rollback. A successful installation
must also distinguish script success from failed runtime registration/readiness.
Keep staging/symlinks/native package-manager transactions implementation-specific.

The empty-prefix uninstall exception also needs narrowing. An empty prefix
proves neither successful provider deregistration nor completion of a requested
data purge. A generic nonzero exit must not be converted to complete success
solely because that directory is empty. Define a narrowly attributable parent-
directory removal case, or require a successful hook and let the host own prefix
removal. This changes existing host behavior and needs conformance coverage.

### 2. Design mandatory-capability negotiation before adding more restrictions

The additive-field rule is appropriate for display hints, not for constraints
that must be enforced. A future mandatory-capability mechanism could let a
publisher say that a target requires a specific host guarantee. Unknown required
capabilities should refuse that target before fetching or executing artifacts.

This cannot make an old reader safe merely by adding another unknown field.
Specify a version/profile boundary old readers already refuse, or use separate
trust directories/domains for online issuing keys during migration. Keep this
mechanism distinct from permissive presentation hints such as panel capabilities
and payment rails. Resolve the migration story before choosing field names.

### 3. Clarify offline trust versus time validity

Section 14.3 says an unreachable issuer directory preserves the last decision;
section 14.6 independently expires use rights after validity plus grace. Clarify
that cached trust material is not a frozen, indefinitely valid authorization
verdict: local expiry must still be evaluated. Also specify what a cached
revocation means and whether any freshness limit is mandatory or host policy.
No universal online dependency should be added accidentally to perpetual use.

### 4. Explain nonce/replay and refresh idempotency explicitly

Presentations have an audience, short lifetime and nonce, but a nonce alone does
not prevent replay. Specify whether repeat artifact reads within that lifetime
are allowed and what an issuer must deduplicate for side-effecting refresh/trial
requests. For a machine-payable refresh, retries must not mint duplicate trials
or apply a settled payment twice. Payment settlement remains the rail's job;
AXP should define proof/retry semantics, not wallets or payment execution.

## Priority

Keep the corrections above small and deploy role-aware readers first. Next,
settle lifecycle outcomes and offline-validity semantics with conformance tests.
Mandatory-capability negotiation needs an explicit compatibility decision; it
should not be smuggled in as another optional field. No central registry,
mandatory payment rail, dependency solver or general package manager is needed.
