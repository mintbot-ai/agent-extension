"""axp — reference implementation of the Agent Extension Protocol (AXP).

Runtime-neutral building blocks any host or publisher tool can use:

* :mod:`axp.manifest` — structural validation, v0.2 compatibility readings,
  and §5 target selection (platforms + ``runtime_version``).
* :mod:`axp.versions` — the §4.3 version / constraint grammar (semver and
  calver, pre-releases, ``^`` / ``~``).
* :mod:`axp.updates` — §7 rules: channels, policy strings, freshness, and the
  consent ratchet (``permissions_widened``).
* :mod:`axp.jcs` — RFC 8785 canonicalization (the signing input).
* :mod:`axp.signing` — ed25519 keygen / sign / verify (``cryptography`` or
  the openssl CLI), the publisher key directory (§8.5) and the transactional
  TOFU :class:`~axp.signing.PinStore` (``decide`` → install → ``commit``).
* :mod:`axp.publish` — publisher tooling behind ``axp init`` / ``axp release``.
* :mod:`axp.cli` — the ``axp`` command (``init | keygen | release | validate |
  canonicalize | sign | verify | target | keydir``).

Stdlib-only except for signing, which works with either the ``cryptography``
package or the ``openssl`` binary — whichever the host has. Host authors:
start with ``docs/HOST-GUIDE.md``.
"""

from .jcs import JCSError, canonicalize, signing_input
from .updates import PolicyError, channel_accepts, is_expired, parse_policy, permissions_widened
from .versions import VersionError, compare, is_newer, parse_constraint, satisfies
from .manifest import ManifestError, ext_id, host_platform, is_axp_manifest, select_target, validate
from .signing import (
    PinStore,
    SigningError,
    TrustDecision,
    generate_private_key_pem,
    key_directory_url,
    parse_key_directory,
    public_key_from_private,
    sign_manifest,
    verify_manifest,
)

__version__ = "0.4.0"

__all__ = [
    "JCSError",
    "ManifestError",
    "PolicyError",
    "VersionError",
    "channel_accepts",
    "compare",
    "is_expired",
    "is_newer",
    "key_directory_url",
    "parse_key_directory",
    "parse_constraint",
    "parse_policy",
    "permissions_widened",
    "satisfies",
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
