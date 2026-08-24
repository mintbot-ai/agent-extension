"""The host adapter the conformance suite drives.

A host under test implements three operations. Exceptions (any Exception)
count as refusal where the case expects one; the suite never inspects
messages beyond the fragments the spec mandates.
"""

from __future__ import annotations

import os
import tempfile
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


def make_adapter() -> Adapter:
    """Fresh adapter per test: the reference one, or the host named by
    AXP_CONFORMANCE_ADAPTER (a module exposing make_adapter())."""
    module_name = os.environ.get("AXP_CONFORMANCE_ADAPTER")
    if module_name:
        return import_module(module_name).make_adapter()
    return ReferenceAdapter()
