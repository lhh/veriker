"""Sweep the degradation oracle over audit_bundle/plugins/ — the surface
THREAT_MODEL row 20 names as NOT reached by its doctrine."""
import json, sys, time, traceback
from pathlib import Path
sys.path.insert(0, ".")
from audit_bundle._degradation import (
    probe_monotonicity, format_report, Severity, DegradationConfigError)
from audit_bundle.verifier import _parse_manifest
from audit_bundle.bundle_manifest import ManifestError
import importlib
P = type(sys)('P')
for _m in ('dispatch_record_wellformed','falsification_negative_test','file_integrity_many_small','fragment_attestation','monotone_growth','re_derivation_invocation','refinement_discharge','source_attributes_consistency','spec_sha_pin','stamp_lattice','three_set_sum_invariant','verifier_identity_tripwire'):
    setattr(P, _m, importlib.import_module('audit_bundle.plugins.'+_m))

BUNDLE = Path(sys.argv[1] if len(sys.argv) > 1
              else "examples/healthcare_diagnosis_minimal")
FIXTURE = json.loads((BUNDLE / "manifest.json").read_text())

CHECKS = [
    ("dispatch_record_wellformed", P.dispatch_record_wellformed.DispatchRecordWellformedCheck),
    ("falsification_negative_test", P.falsification_negative_test.FalsificationNegativeTestCheck),
    ("file_integrity_many_small", P.file_integrity_many_small.FileIntegrityManySmall),
    ("fragment_attestation", P.fragment_attestation.FragmentAttestationCheck),
    ("monotone_growth", P.monotone_growth.MonotoneGrowthCheck),
    ("re_derivation_invocation", P.re_derivation_invocation.ReDerivationInvocationCheck),
    ("refinement_discharge", P.refinement_discharge.RefinementDischargeCheck),
    ("source_attributes_consistency", P.source_attributes_consistency.SourceAttributesConsistencyCheck),
    ("spec_sha_pin", P.spec_sha_pin.SpecShaPinCheck),
    ("stamp_lattice", P.stamp_lattice.StampLatticeCheck),
    ("three_set_sum_invariant", P.three_set_sum_invariant.ThreeSetSumInvariantCheck),
    ("verifier_identity_tripwire", P.verifier_identity_tripwire.VerifierIdentityTripwireCheck),
]

def make_run(check):
    def run(root):
        try:
            m = _parse_manifest(json.dumps(root).encode(), BUNDLE)
        except ManifestError:
            # The parse boundary refused. A real, in-pipeline fail-closed.
            return Severity.REJECT, ("MANIFEST_PARSE_REFUSED",), False
        except Exception as e:
            # A crash is could-not-conclude, never a substantive verdict (C5).
            return Severity.ERROR, (f"PARSE_CRASH:{type(e).__name__}",), False
        try:
            r = check.check(BUNDLE, m)
        except Exception as e:
            return Severity.ERROR, (f"PLUGIN_CRASH:{type(e).__name__}",), True
        sev = Severity.PASS if getattr(r, "ok", False) else Severity.REJECT
        code = getattr(r, "reason_code", None)
        return sev, ((str(code),) if code else ()), True
    return run

print(f"# bundle: {BUNDLE}   nodes in manifest: ", end="")
from audit_bundle._degradation import _walk
print(sum(1 for _ in _walk(FIXTURE)))
for name, cls in CHECKS:
    t0 = time.time()
    try:
        rep = probe_monotonicity(FIXTURE, make_run(cls()))
    except DegradationConfigError as e:
        print(f"\n## {name}\n  SKIPPED (vacuity gate): {str(e)[:150]}")
        continue
    except Exception as e:
        print(f"\n## {name}\n  HARNESS ERROR: {type(e).__name__}: {str(e)[:200]}")
        continue
    dt = time.time() - t0
    c = rep.counts
    print(f"\n## {name}  [{dt:.1f}s]")
    print(f"  probed={c['paths_probed']}/{c['paths']} indifferent={c['paths_indifferent_v2']} "
          f"runs={c['distinct_runs']} TIER1={c['findings_tier1']} TIER2={c['findings_tier2']} "
          f"disclosures={c['disclosures']} upstream_only={c['paths_upstream_only_v4']} VACUOUS={rep.vacuous}")
    for f in rep.findings:
        print(f"    [TIER-{f.tier}] {f.relation} {list(f.path)!r} rung={f.rung}: "
              f"{f.base_rung}={f.base_severity.name} -> {f.rung}={f.rung_severity.name}")
