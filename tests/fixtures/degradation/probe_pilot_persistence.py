"""Target 2 of the internal design notes: MR-4 through the five declared
pilots' OWN `verify.py --bundle-dir`, exit codes only (severity_only=True, declared).

Tamper = the first `files` entry under outputs/ or payload/ (alphabetical) := "0"*64.
Paths: len(path) <= 1. A pilot whose baseline is not PASS, or that has no tamper
target, is REPORTED as unrunnable — never swapped for another pilot.
"""
import json, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from audit_bundle._degradation import (  # noqa: E402
    DegradationConfigError, probe_persistence, exit_code_adapter, format_report, _walk)

PILOTS = ["chat_log_redaction_minimal", "dc_emissions_mrv_minimal",
          "healthcare_diagnosis_minimal", "legal_contract_minimal", "spectra_minimal"]
ENV = {"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"}

for pilot in (sys.argv[1:] or PILOTS):
    src = ROOT / "examples" / pilot
    fix = json.loads((src / "manifest.json").read_text())
    targets = sorted(k for k in fix.get("files", {}) if k.startswith(("outputs/", "payload/")))
    print(f"\n===== {pilot}", flush=True)
    if not targets:
        # Still RUN the untouched baseline once, so the report carries what the pilot
        # says about its own copy (claims lens, stage 5: an asserted baseline REJECT
        # had no committed evidence).
        w = Path(tempfile.mkdtemp(prefix=f"degpilot-{pilot}-"))
        shutil.copytree(src, w / "b", ignore=shutil.ignore_patterns("__pycache__"))
        p = subprocess.run([sys.executable, str(src / "verify.py"), "--bundle-dir", str(w / "b")],
                           capture_output=True, text=True, timeout=300, env=ENV, cwd=str(ROOT))
        shutil.rmtree(w, ignore_errors=True)
        lines = [l for l in (p.stderr or p.stdout).splitlines() if l.strip()]
        print(f"UNRUNNABLE: no files entry under outputs/ or payload/ to tamper; baseline on a copy: exit={p.returncode}")
        for l in lines[:4]:
            print("   ", l[:160])
        continue
    tamper = (("files", targets[0]), "0" * 64)
    work = Path(tempfile.mkdtemp(prefix=f"degpilot-{pilot}-"))
    n = [0]

    def invoke(root, _src=src, _work=work, _pilot=pilot, _n=n):
        _n[0] += 1
        bun = _work / f"b{_n[0]}"
        shutil.copytree(_src, bun, ignore=shutil.ignore_patterns("__pycache__"))
        (bun / "manifest.json").write_text(json.dumps(root, indent=2))
        p = subprocess.run([sys.executable, str(_src / "verify.py"), "--bundle-dir", str(bun)],
                           capture_output=True, text=True, timeout=300, env=ENV, cwd=str(ROOT))
        shutil.rmtree(bun, ignore_errors=True)
        return p.returncode, (p.stderr or p.stdout)

    run = exit_code_adapter(invoke, crash_detector=lambda e: "Traceback" in e)
    paths = [p for p, _ in _walk(fix) if len(p) == 1]
    print(f"# tamper={tamper[0]} paths={len(paths)} (len==1)")
    t0 = time.time()
    try:
        rep = probe_persistence(fix, run, tamper=tamper, paths=paths, severity_only=True)
    except DegradationConfigError as e:
        print(f"UNRUNNABLE (config error): {e}")
        shutil.rmtree(work, ignore_errors=True)
        continue
    print(f"# {time.time()-t0:.0f}s, {n[0]} runs")
    print(format_report(rep))
    for leg in rep.legs:
        print(f"  {list(leg.path)!r} {leg.rung} -> {leg.severity.name} {[r[:60] for r in leg.reasons][:2]}")
    shutil.rmtree(work, ignore_errors=True)
