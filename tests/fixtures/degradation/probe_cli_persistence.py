"""Target 1 of the internal design notes: MR-4 through the PRODUCTION CLI
(`veriker/cli/verify.py`, anchored, kit loaded) on examples/climate_emission_minimal.

Adapter: the fixture is the manifest dict; the bundle on disk is a fresh copy per
leg; `--verdict-out` face -> (severity, reasons, spoke). Reasons are
`f"{code}:{detail}"` from face.verdict.reasons (a bare code is shared across sites).
The T2 forgery is content-addressed: the adapter writes whichever bytes the
manifest's declared sha for outputs/climate_total_scope3.json names, so the
tamper stays a (path, value) on the fixture.

Usage: python tests/fixtures/degradation/probe_cli_persistence.py T1|T2 [max_depth]
"""
import hashlib, json, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from audit_bundle._degradation import (  # noqa: E402
    DegradationConfigError, Severity, probe_persistence, format_report, _walk)

SRC = ROOT / "examples/climate_emission_minimal"
FIX = json.loads((SRC / "manifest.json").read_text())
OUT_REL = "outputs/climate_total_scope3.json"
HONEST = (SRC / OUT_REL).read_bytes()
FORGED = json.dumps({"value": 52931.44}, indent=2).encode() + b"\n"
STORE = {hashlib.sha256(b).hexdigest(): b for b in (HONEST, FORGED)}
which = sys.argv[1] if len(sys.argv) > 1 else "T1"
max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 2
TAMPER = {
    "T1": (("files", OUT_REL), "0" * 64),
    "T2": (("files", OUT_REL), hashlib.sha256(FORGED).hexdigest()),
}[which]

WORK = Path(tempfile.mkdtemp(prefix=f"degpersist-{which}-"))
ARGS = ["--spec-anchor", str(SRC / "spec_pinned/climate.spec.json"),
        str(SRC / "spec_pinned/climate_emission.spec.json"),
        "--primitives", str(SRC / "auditor_kit.py")]
ENV = {"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin", "HOME": str(WORK)}
UPSTREAM_CODES = {"MalformedManifest", "SchemaVersionError"}
n = [0]

def invoke(root):
    n[0] += 1
    bun = WORK / f"b{n[0]}"
    shutil.copytree(SRC, bun, ignore=shutil.ignore_patterns("__pycache__"))
    declared = root.get("files", {}).get(OUT_REL) if isinstance(root, dict) and isinstance(root.get("files"), dict) else None
    if isinstance(declared, str) and declared in STORE:
        (bun / OUT_REL).write_bytes(STORE[declared])
    (bun / "manifest.json").write_text(json.dumps(root, indent=2))
    face_p = WORK / f"face{n[0]}.json"
    p = subprocess.run([sys.executable, str(ROOT / "veriker/cli/verify.py"), "--bundle-dir", str(bun),
                        *ARGS, "--verdict-out", str(face_p)],
                       capture_output=True, text=True, timeout=300, env=ENV, cwd=str(ROOT))
    shutil.rmtree(bun, ignore_errors=True)
    face = json.loads(face_p.read_text()) if face_p.exists() else None
    if face_p.exists():
        face_p.unlink()
    if p.returncode == 0:
        return Severity.PASS, (), True
    if p.returncode == 1:
        reasons = _reasons(face, p)
        # Target vocabulary, stated: a manifest that never parsed or failed the schema
        # gate was refused UPSTREAM of every check; the check under test did not speak.
        upstream = reasons and all(r.split(":")[0] in UPSTREAM_CODES for r in reasons)
        return Severity.REJECT, reasons, not upstream
    if p.returncode == 2:
        kind = ((face or {}).get("verdict") or {}).get("error_kind") or ""
        # VERIFIER_INTERNAL_ERROR is the CLI's own catch-all crash label (veriker/cli/verify.py
        # `face["reason_codes"].append("VERIFIER_INTERNAL_ERROR")`): a traceback the CLI
        # caught is still a crash in the ratified algebra, and scoring it ERROR_CLEAN filed
        # it as `demoted` on the first run (2026-09-12) — noise wearing a finding's label.
        crashed = ("Traceback" in (p.stderr or "") or str(kind).upper().endswith("CRASH")
                   or "VERIFIER_INTERNAL_ERROR" in ((face or {}).get("reason_codes") or []))
        return (Severity.ERROR_CRASH if crashed else Severity.ERROR_CLEAN), _reasons(face, p), True
    raise DegradationConfigError(f"exit {p.returncode} unmapped: {(p.stderr or p.stdout)[:300]!r}")

def _reasons(face, p):
    if face and isinstance(face.get("verdict"), dict) and face["verdict"].get("reasons"):
        return tuple(f"{r.get('code')}:{r.get('detail','')}" for r in face["verdict"]["reasons"])
    if face and face.get("reason_codes"):
        return tuple(f"{c}:" for c in face["reason_codes"])
    return ((p.stderr or p.stdout).strip().splitlines() or ["<no face>"])[-1:]

paths = [p for p, _ in _walk(FIX) if 0 < len(p) <= max_depth]
print(f"# {which} tamper={TAMPER[0]} declared projection: {len(paths)} nodes with len<=({max_depth})", flush=True)
t0 = time.time()
try:
    rep = probe_persistence(FIX, invoke, tamper=TAMPER, paths=paths)
except DegradationConfigError as e:
    print(f"CONFIG ERROR: {e}")
    sys.exit(3)
print(f"# {time.time()-t0:.0f}s, {n[0]} CLI runs")
print(format_report(rep))
print("# legs:")
for leg in rep.legs:
    print(f"  {list(leg.path)!r} {leg.rung} -> {leg.severity.name} {[r[:70] for r in leg.reasons][:3]}")
shutil.rmtree(WORK, ignore_errors=True)
