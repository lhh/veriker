"""auditor_entry.py — the auditor's single anchored entry point for this pilot.

Both auditor-side tools -- `verify.py` (verdict) and `hard_negatives.py`
(failure-telemetry export) -- construct their verifier HERE, once. They used to
be unrelated programs: verify.py built an anchored BundleVerifier, and the
miner read the bundle's files directly and never verified anything at all. That
split is the defect this module closes, and keeping ONE constructor is what
stops it reopening -- a hardening applied to the verdict path that the mining
path did not inherit is exactly how the miner drifted the first time.

WHY MINING MUST BE GATED ON A VERDICT
-------------------------------------
A hard negative asserts something about a MODEL: "this input state made the
deployed twin publish physically inadmissible loads." That assertion is only
sound if the loads under examination are the ones the producer actually
published. An ungated miner cannot tell the two apart -- MEASURED on this
pilot: a clean bundle with 60 payload rows edited after emission (FL +900 N)
yielded 60 ranked "hard negatives" stamped with a valid-looking spec sha and
attributed to the clean bundle_id, at exit 0. On fleet telemetry arriving over
the air, "the model extrapolated" and "the file was corrupted in transit" are
precisely the two hypotheses the export exists to separate.

WHY IT IS NOT "REFUSE UNLESS THE BUNDLE PASSES"
-----------------------------------------------
The bundle worth mining is the one that FAILS -- the drift bundle is a REJECT,
and a naive pass-gate would refuse every bundle that has negatives in it and
admit only the ones that have none. The distinction that matters is not
pass/fail but WHICH check concluded:

  * authenticity / structure / anchor  -> the artifact is not what the producer
    emitted (or we hold no authority to judge it). Nothing can be attributed to
    the model. REFUSE.
  * the equilibrium residual channels  -> the artifact is authentic and the
    physics is violated. That is the finding. ADMIT and mine it.

ADMISSION IS DENY-BY-DEFAULT over `check_name`, never over reason prose: the
allowlist is derived from the anchored spec's own type keys, so a channel added
to the spec is followed automatically and any OTHER check that fires -- today's
`file_integrity`, `spec_pinned_dispatch:coverage`, or one that does not exist
yet -- refuses the run rather than being silently ignored.

Keying on `check_name` and not on `reason_code` is deliberate: a typed-check
plugin's own reason_code is overwritten with the constant `plugin_failed`
before it reaches the verdict face, so `check_name` is the only field that
identifies WHICH check concluded.

Stdlib only apart from `audit_bundle` itself.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]
for _p in (_PKG_ROOT, _HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.rederivation.kit import load_primitive_kit  # noqa: E402
from audit_bundle.rederivation.reason_codes import (  # noqa: E402
    RE_DERIVATION_MISMATCH,
)
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from audit_bundle.work_set import WorkSet  # noqa: E402

KIT_PATH = _HERE / "auditor_kit.py"
SPEC_PATH = _HERE / "spec_pinned" / "corner_load_equilibrium.spec.json"
SPEC_SOURCES = (SPEC_PATH,)
# The auditor's WORK-SET as a committed FILE, for the shipped CLI's --work-set
# (verify.py prefills it). The library path keeps the DERIVED form below
# (_work_set) so a channel added to the spec is pinned automatically; the
# parity test in tests/test_corner_load_equilibrium_minimal.py holds the two
# equal, so the file cannot drift from the spec without a red test.
WORK_SET_PATH = _HERE / "spec_pinned" / "corner_load_equilibrium.work_set.json"

# The one reason code a residual channel may carry and still be mineable. A
# leg that timed out, raised, or could not compare did NOT establish a residual
# -- admitting it would let "we don't know" be exported as "the model is wrong".
# BOUND to the canonical vocabulary, never re-spelled: this constant carried a
# pre-collapse literal ("REDERIVATION_MISMATCH") written before the 156-spelling
# collapse landed, and a mining gate whose admissible code matches nothing the
# verifier emits refuses every bundle -- including the violation it exists to
# export.
_MINEABLE_LEG_CODE = RE_DERIVATION_MISMATCH

# Fired by the re-derivation surface when no leg ended in a match. On a genuine
# all-channel violation it accompanies the mismatches; it is admissible ONLY
# because a dispatch leg must also be present (see `admit_for_mining`), which
# is what separates "every channel is wrong" from "nothing was compared".
_SURFACE_CHECK = "re_derivation_surface"


class MiningRefused(Exception):
    """The bundle is not a sound basis for attributing failures to a model.

    Raised for bundle authenticity/structure/anchor conclusions and for any
    check the admission policy does not recognise. This is a could-not-conclude
    ABOUT THE MODEL -- it says nothing about whether the twin is good -- so
    callers map it to exit 2, never to a finding.
    """


@dataclass(frozen=True)
class MiningAuthority:
    """The authority a mined negative is attributed under.

    Every field is taken from the objects that actually reached the verdict --
    the anchor that judged and the verdict it produced -- never recomputed
    alongside them. The miner previously stamped `sha256(<its own spec copy>)`,
    which is constant across every run and therefore attests to the tool rather
    than to any verdict.
    """

    bundle_id: str | None
    verdict_state: str
    spec_provenance: tuple[dict, ...]
    admitted_reasons: tuple[dict, ...]

    def as_record(self) -> dict:
        anchored = [
            {"spec_id": p.get("spec_id"), "sha256": p.get("sha256")}
            for p in self.spec_provenance
        ]
        return {
            "bundle_id": self.bundle_id,
            "verdict_state": self.verdict_state,
            "anchored_specs": anchored,
            # Retained as a scalar for consumers that carry one spec: this
            # pilot anchors exactly one file. Sourced from the anchor's own
            # provenance record, not hashed independently.
            "anchored_spec_sha256": anchored[0]["sha256"] if anchored else None,
            "spec_id": anchored[0]["spec_id"] if anchored else None,
            "admitted_reasons": list(self.admitted_reasons),
        }


def _work_set() -> WorkSet:
    """The auditor's WORK-SET: every output_id this bundle must deliver, pinned
    to the anchored type that judges it — derived from the ANCHORED spec's own
    type keys.

    WHY IT EXISTS. Under spec-pinned dispatch the producer's last degree of
    freedom is WHICH ROW of the auditor's binding table judges each claim, and
    for this pilot that freedom was enough to publish a physically inadmissible
    load set at exit 0 (MEASURED 2026-08-31): offset all four corners by +15 N
    -- the vertical equilibrium sum moves 60.5 N against an epsilon of 40 N,
    the roll DIFFERENCE is untouched -- then retype that one output as the roll
    residual. `manifest.json` is not hash-covered, so it costs one string.

    The generic anchored-type coverage channel catches the plain retype (the
    vertical rule then judges nothing). It does NOT catch the retype paired
    with a decoy output that exercises the vertical type honestly (measured
    2026-09-01, exit 0), nor the claim simply DROPPED with a decoy in its
    place, nor -- the hole the per-output `role_policy` that preceded this
    left open -- an EXTRA output under a valid type that nobody asked for
    (measured 2026-09-01: exit 0, face reading "role policy APPLIED over 3
    output_id(s)" having judged four). The work-set is one invariant over all
    of them: the bundle delivers exactly this multiset of output_ids, each
    under its pinned type. Deny-by-default; duplicates are findings.

    DERIVED, not hardcoded, so a channel added to the spec is pinned
    automatically -- the same reason `_anchored_channel_checks` is derived.
    This pilot names each output after the channel it reports, so the identity
    map is the policy. Because the enumeration comes from a committed artifact
    the anchor also pins, the work-set carries provenance EXTERNAL_STRUCTURE
    with that spec's sha256 as its source_sha -- the same sha the anchor lists,
    so the face can be checked against `spec_anchor_provenance`.

    AUDITOR-SIDE: read from SPEC_PATH, the committed `spec_pinned/` copy that
    `SpecAnchor.from_files` also reads and refuses to take from the bundle.
    """
    raw = SPEC_PATH.read_bytes()
    spec = json.loads(raw)
    return WorkSet.declare(
        {type_key: type_key for type_key in spec["types"]},
        source=(
            f"anchored spec {spec['spec_id']} ({SPEC_PATH.name}): one output per "
            "type key, output_id == type key"
        ),
        provenance="EXTERNAL_STRUCTURE",
        source_sha=hashlib.sha256(raw).hexdigest(),
    )


def _anchored_channel_checks() -> frozenset[str]:
    """Dispatch-leg check names, derived from the ANCHORED spec's type keys.

    Derived rather than hardcoded so the policy follows the spec: a channel
    added to the spec becomes mineable, and a check name that is not a channel
    (`spec_pinned_dispatch:coverage`, which is what a deleted `manifest.outputs`
    trips) is not admitted by accident.
    """
    spec = json.loads(SPEC_PATH.read_bytes())
    return frozenset(f"spec_pinned_dispatch:{t}" for t in spec["types"])


def build_verifier(bundle_dir: Path) -> tuple[BundleVerifier, SpecAnchor]:
    """The pilot's anchored verifier. THE definition -- both tools call this.

    Anchored via SpecAnchor.from_files(..., forbid_within=bundle_dir) so a
    producer-shipped spec/ copy yields a SHA the anchor does not list,
    require_rederivation=True so a bundle that re-derives nothing is a
    could-not-conclude rather than a quiet PASS, and the work-set derived from
    the anchored spec so WHICH claims arrive and WHICH rule judges each is not
    the producer's choice.
    """
    load_primitive_kit([KIT_PATH], forbid_within=bundle_dir)
    anchor = SpecAnchor.from_files(list(SPEC_SOURCES), forbid_within=bundle_dir)
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor,
        require_rederivation=True,
        # Which claims must arrive, and which anchored rule judges each, is the
        # AUDITOR's call, not the producer's (see _work_set). Without this a
        # retyped output verified green on a 60.5 N vertical residual against
        # an epsilon of 40 N, and an extra unasked-for output rode a valid type
        # to exit 0.
        work_set=_work_set(),
    )
    return verifier, anchor


def admit_for_mining(bundle_dir: Path) -> MiningAuthority:
    """Verify `bundle_dir`; return the authority to mine it, or refuse.

    ADMIT when the verdict is OK (an authentic bundle whose channels all
    matched -- the export will be empty, which is itself a result), or when
    every reason is a residual-channel mismatch on an anchored channel.
    REFUSE otherwise, including on ERROR: a verifier that could not conclude
    has established nothing to attribute.
    """
    bundle_dir = Path(bundle_dir).resolve()
    verifier, anchor = build_verifier(bundle_dir)
    verdict = verifier.verify(bundle_dir)
    state = str(getattr(verdict.state, "value", verdict.state))

    if anchor.provenance is None:
        raise MiningRefused(
            "the spec anchor carries no provenance (raw SpecAnchor constructor) "
            "-- a negative cannot name the authority it was judged under"
        )

    channel_checks = _anchored_channel_checks()
    allowed = channel_checks | {_SURFACE_CHECK}

    if verdict.ok:
        admitted: tuple[dict, ...] = ()
    else:
        if state != "REJECT":
            raise MiningRefused(
                f"verdict state {state} -- the verifier could not conclude about "
                f"this bundle, so nothing in it can be attributed to the model "
                f"({'; '.join(r.check_name for r in verdict.reasons) or 'no reasons'})"
            )
        unrecognised = [r for r in verdict.reasons if r.check_name not in allowed]
        if unrecognised:
            raise MiningRefused(
                "the bundle was rejected for reasons that are not equilibrium "
                "residuals, so its published loads are not established to be the "
                "ones the producer emitted: "
                + "; ".join(f"[{r.check_name}] {r.code}" for r in unrecognised)
            )
        legs = [r for r in verdict.reasons if r.check_name in channel_checks]
        if not legs:
            raise MiningRefused(
                "no residual channel reported a comparison -- nothing was "
                "re-derived, so there is no finding to export"
            )
        bad = [r for r in legs if r.code != _MINEABLE_LEG_CODE]
        if bad:
            raise MiningRefused(
                "a residual channel did not establish a residual (a leg that "
                "timed out or raised is not a model failure): "
                + "; ".join(f"[{r.check_name}] {r.code}" for r in bad)
            )
        admitted = tuple(
            {"check_name": r.check_name, "reason_code": r.code} for r in verdict.reasons
        )

    manifest = json.loads((bundle_dir / "manifest.json").read_bytes())
    return MiningAuthority(
        bundle_id=manifest.get("bundle_id"),
        verdict_state=state,
        spec_provenance=tuple(anchor.provenance),
        admitted_reasons=admitted,
    )
