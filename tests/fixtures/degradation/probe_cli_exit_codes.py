"""Probe the real tri-state CLI through its EXIT CODE only -- the same adapter a
foreign bounty target would use. Scoped to a declared subtree (see PATHS)."""
import json, shutil, subprocess, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, ".")
from audit_bundle._degradation import (
    probe_monotonicity, exit_code_adapter, format_report, _walk)

SRC = Path("examples/climate_emission_minimal")
FIX = json.loads((SRC / "manifest.json").read_text())
WORK = Path(tempfile.mkdtemp(prefix="degcli-"))
BUN = WORK / "bundle"
shutil.copytree(SRC, BUN)

def invoke(root):
    (BUN / "manifest.json").write_text(json.dumps(root, indent=2))
    p = subprocess.run(
        [sys.executable, "veriker/cli/verify.py", "--bundle-dir", str(BUN),
         "--spec-anchor",
         "examples/climate_emission_minimal/spec_pinned/climate.spec.json",
         "examples/climate_emission_minimal/spec_pinned/climate_emission.spec.json",
         "--primitives", "examples/climate_emission_minimal/auditor_kit.py"],
        capture_output=True, text=True, timeout=180)
    return p.returncode, (p.stderr or p.stdout)

# DECLARED PROJECTION: the full 63-node walk is ~280 subprocess runs. Scoped to
# the dispatch_records subtree + the top level. Narrowing the denominator is
# stated, never silent.
ALL = [p for p, _ in _walk(FIX)]
PATHS = [p for p in ALL if len(p) <= 1][:20]
print(f"# declared projection: {len(PATHS)} of {len(ALL)} nodes")
t0 = time.time()
rep = probe_monotonicity(FIX, exit_code_adapter(invoke), paths=PATHS)
print(f"# {time.time()-t0:.0f}s")
print(format_report(rep))
shutil.rmtree(WORK, ignore_errors=True)
