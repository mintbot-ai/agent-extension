"""axp — reference implementation of the Agent Extension Protocol (AXP).

Runtime-neutral building blocks any host or publisher tool can use:

* :mod:`axp.manifest` — structural validation, v0.2 compatibility readings,
  and §5 target selection.
* :mod:`axp.jcs` — RFC 8785 canonicalization (the signing input).
* :mod:`axp.signing` — ed25519 keygen / sign / verify (``cryptography`` or
  the openssl CLI) and the TOFU :class:`~axp.signing.PinStore`.
* :mod:`axp.cli` — the ``axp`` command (``validate | canonicalize | keygen |
  sign | verify | target``).

Stdlib-only except for signing, which works with either the ``cryptography``
package or the ``openssl`` binary — whichever the host has.
"""

from .jcs import JCSError, canonicalize, signing_input
from .manifest import ManifestError, ext_id, host_platform, is_axp_manifest, select_target, validate
from .signing import (
    PinStore,
    SigningError,
    TrustDecision,
    generate_private_key_pem,
    public_key_from_private,
    sign_manifest,
    verify_manifest,
)

__version__ = "0.3.0"

__all__ = [
    "JCSError",
    "ManifestError",
    "PinStore",
    "SigningError",
    "TrustDecision",
    "__version__",
    "canonicalize",
    "ext_id",
    "generate_private_key_pem",
    "host_platform",
    "is_axp_manifest",
    "public_key_from_private",
    "select_target",
    "sign_manifest",
    "signing_input",
    "validate",
    "verify_manifest",
]
