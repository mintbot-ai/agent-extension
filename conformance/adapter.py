"""The host adapter the conformance suite drives.

A host under test implements three operations. Exceptions (any Exception)
count as refusal where the case expects one; the suite never inspects
messages beyond the fragments the spec mandates.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime
from importlib import import_module
from pathlib import Path
from typing import Protocol


class Adapter(Protocol):
    def validate(self, manifest: dict, origin: str | None = None) -> None:
        """Raise on a manifest the host must refuse; return on acceptance."""

    def select_runtime(self, manifest: dict, runtimes: tuple[str, ...], platform: str) -> str:
        """Return the runtime id of the target the host would install; raise when none."""

    def evaluate_trust(self, ext_id: str, manifest: dict) -> tuple[bool, str]:
        """Run the section 8 trust decision against persistent per-adapter state.
        Returns ``(accepted, action)`` with action in
        pin | same-key | announce | rotate | recover | unsigned | refuse."""

    def evaluate_trust_with_directory(self, ext_id: str, manifest: dict,
                                      directory_keys: list[str]) -> tuple[bool, str]:
        """OPTIONAL (section 8.5): the same decision with the publisher key
        directory consulted. Hosts that do not implement it skip those cases."""

    def verify_entitlement(self, manifest: dict, entitlement: dict, holder: str,
                           key_directory: dict, now: datetime) -> tuple[bool, str]:
        """OPTIONAL (section 14, commerce-capable hosts): the entitlement check
        for ``manifest`` as the host runs it before an install or at its
        periodic re-check — ``holder`` is the host's own key, ``key_directory``
        the issuer's directory document as fetched, ``now`` the clock.
        Returns ``(valid, status)`` with status in valid | grace | expired |
        not_yet_valid | wrong_extension | wrong_holder | untrusted_issuer |
        untrusted_key | bad_signature | malformed."""


class ReferenceAdapter:
    """The `axp` package itself — what any other host is measured against."""

    def __init__(self) -> None:
        from axp.signing import PinStore
        self._tmp = tempfile.TemporaryDirectory(prefix="axp-conformance-")
        self._pins = PinStore(Path(self._tmp.name) / "pins.json")

    def validate(self, manifest: dict, origin: str | None = None) -> None:
        from axp.manifest import validate
        validate(manifest, origin=origin)

    def select_runtime(self, manifest: dict, runtimes: tuple[str, ...], platform: str) -> str:
        from axp.manifest import select_target
        _target, runtime = select_target(manifest, runtimes=runtimes, platform=platform)
        return runtime

    def evaluate_trust(self, ext_id: str, manifest: dict) -> tuple[bool, str]:
        decision = self._pins.evaluate(ext_id, manifest)
        return decision.accepted, decision.action

    def evaluate_trust_with_directory(self, ext_id: str, manifest: dict,
                                      directory_keys: list[str]) -> tuple[bool, str]:
        decision = self._pins.evaluate(ext_id, manifest, directory_keys=directory_keys)
        return decision.accepted, decision.action

    def verify_entitlement(self, manifest: dict, entitlement: dict, holder: str,
                           key_directory: dict, now: datetime) -> tuple[bool, str]:
        from axp import entitlements
        from axp.manifest import validate
        from axp.signing import ROLE_ENTITLEMENT, SigningError, parse_key_directory
        summary = validate(manifest)
        commerce = summary["commerce"] or {"issuers": [summary["publisher"]]}
        issuer = str(entitlement.get("issuer") or "")
        if issuer not in commerce["issuers"]:
            return False, "untrusted_issuer"
        try:
            issuer_keys = parse_key_directory(key_directory, publisher=issuer, name=summary["ext_id"],
                                              role=ROLE_ENTITLEMENT)
        except SigningError:
            return False, "untrusted_key"
        verdict = entitlements.verify_entitlement(
            entitlement, extension=summary["ext_id"], holder=holder, issuer_keys=issuer_keys,
            issuers=commerce["issuers"], now=now,
        )
        return verdict.valid, verdict.status


def make_adapter() -> Adapter:
    """Fresh adapter per test: the reference one, or the host named by
    AXP_CONFORMANCE_ADAPTER (a module exposing make_adapter())."""
    module_name = os.environ.get("AXP_CONFORMANCE_ADAPTER")
    if module_name:
        return import_module(module_name).make_adapter()
    return ReferenceAdapter()
