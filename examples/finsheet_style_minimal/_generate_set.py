#!/usr/bin/env python3
"""_generate_set.py — PRODUCER-side generator for the FinSheet-STYLE set.

Builds 24 synthetic private-equity portfolio-monitoring workbooks (6 layouts
x 4 sizes) modelled on the recipe FinSheet-Bench (arXiv 2603.07316) describes,
instantiates 16 question templates on each, and computes GOLD answers with its
OWN arithmetic. It imports nothing from `audit_bundle` (sibling ratchet): the
verifier primitive agreeing with these gold answers on every honest bundle is
the faithfulness test, and it can only be a test if the two never share code.

This is a REPRODUCTION OF THE SHAPE, never FinSheet-Bench itself — the paper
states no data release. Say "FinSheet-style" everywhere.

Outputs under --out-dir:
  workbooks/<file_id>.xlsx
  questions.json      [{file_id, qid, template, tier, kind, text, gold, query,
                        answer_kind}]  — `query` is the AUDITOR's sheet-query-v1
                        document for that question on that workbook
  set_manifest.json   {file_id: {sha256, layout, size, companies, funds}}

Usage:
    python examples/finsheet_style_minimal/_generate_set.py --out-dir /tmp/finsheet_set
    python examples/finsheet_style_minimal/_generate_set.py --out-dir X --only L2_S1
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

sys.dont_write_bytecode = True

try:
    import openpyxl
    from openpyxl.styles import Alignment, Font
except ImportError:  # pragma: no cover
    print(
        "openpyxl is required to GENERATE the set (the verifier does not need it)",
        file=sys.stderr,
    )
    raise

SET_VERSION = "finsheet-style-set-v1"
BASE_SEED = 20260902

ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII"]
SECTORS = [
    "Healthcare",
    "Software",
    "Industrials",
    "Consumer",
    "Financial Services",
    "Energy",
    "Business Services",
    "Retail",
]
GEOS = ["North America", "Europe", "Asia-Pacific", "Latin America"]
_ADJ = [
    "Blue",
    "Northern",
    "Summit",
    "Harbor",
    "Quartz",
    "Cedar",
    "Atlas",
    "Meridian",
    "Silver",
    "Granite",
    "Beacon",
    "Willow",
    "Copper",
    "Pioneer",
    "Vertex",
    "Crescent",
    "Ember",
    "Falcon",
    "Juniper",
    "Lumen",
    "Maple",
    "Onyx",
    "Ridge",
    "Sable",
    "Tidal",
    "Union",
    "Vantage",
    "Zenith",
    "Aster",
    "Boreal",
    "Cobalt",
    "Delta",
]
_NOUN = [
    "Health",
    "Systems",
    "Logistics",
    "Foods",
    "Analytics",
    "Medical",
    "Capital",
    "Networks",
    "Robotics",
    "Diagnostics",
    "Labs",
    "Freight",
    "Retail",
    "Energy",
    "Payments",
    "Software",
    "Devices",
    "Brands",
    "Materials",
    "Therapeutics",
    "Insurance",
    "Mobility",
    "Packaging",
    "Security",
    "Learning",
    "Water",
    "Media",
    "Components",
    "Studios",
    "Clinics",
    "Grid",
    "Textiles",
]
_SUFFIX = ["", "", "", " Group", " Holdings", " Inc", " Ltd", " Co"]

SIZES = {
    "S1": (8, 1),
    "S2": (24, 2),
    "S3": (72, 4),
    "S4": (152, 8),
}
LAYOUTS = ["L1", "L2", "L3", "L4", "L5", "L6"]

# Header texts per layout family. "plain" for L1/L2/L3/L5; "multi" (multi-line
# cells) for L4/L6.
HEADERS_PLAIN = {
    "company": "Company",
    "sector": "Sector",
    "geo": "Geography",
    "date": "Investment Date",
    "invested": "Invested Capital ($m)",
    "realized": "Realized Value ($m)",
    "nav": "Unrealized Value ($m)",
    "total": "Total Value ($m)",
    "moic": "MOIC (x)",
    "own": "Ownership (%)",
    "status": "Status",
}
HEADERS_MULTI = {
    "company": "Portfolio\nCompany",
    "sector": "Sector",
    "geo": "Region",
    "date": "Entry\nDate",
    "invested": "Invested\nCapital\n($m)",
    "realized": "Realized\nValue\n($m)",
    "nav": "Unrealized\nValue (NAV)\n($m)",
    "total": "Total\nValue\n($m)",
    "moic": "Gross\nMOIC (x)",
    "own": "Fully Diluted\nOwnership (%)",
    "status": "Status",
}
COLUMN_ORDER = [
    "company",
    "sector",
    "geo",
    "date",
    "invested",
    "realized",
    "nav",
    "total",
    "moic",
    "own",
    "status",
]


def q2(x: Decimal) -> Decimal:
    return x.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


_WS = re.compile(r"\s+")


def norm(s: object) -> str:
    return _WS.sub(" ", str(s)).strip().casefold()


# ---------------------------------------------------------------------------
# Portfolio synthesis
# ---------------------------------------------------------------------------


def _company_names(rng: random.Random, n: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    while len(out) < n:
        name = f"{rng.choice(_ADJ)} {rng.choice(_NOUN)}{rng.choice(_SUFFIX)}"
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def synthesize(rng: random.Random, n_companies: int, n_funds: int) -> list[dict]:
    """Records with Decimal money fields. NAV and MOIC are unique across the
    whole portfolio so argmax/topk never tie."""
    names = _company_names(rng, n_companies)
    used_nav: set[Decimal] = set()
    used_moic: set[Decimal] = set()
    used_inv: set[Decimal] = set()
    recs: list[dict] = []
    for i, name in enumerate(names):
        fund = f"Fund {ROMAN[i % n_funds]}"
        exited = rng.random() < 0.25
        while True:
            invested = q2(Decimal(rng.uniform(2.0, 150.0)))
            if invested not in used_inv:
                break
        used_inv.add(invested)
        if exited:
            realized = q2(invested * Decimal(rng.uniform(0.3, 4.5)))
            nav = Decimal("0.00")
        else:
            nav_try = 0
            while True:
                nav = q2(invested * Decimal(rng.uniform(0.5, 3.5)))
                nav_try += 1
                if nav not in used_nav and nav != 0:
                    break
            realized = (
                q2(invested * Decimal(rng.uniform(0.1, 0.8)))
                if rng.random() < 0.2
                else Decimal("0.00")
            )
        used_nav.add(nav)
        total = q2(realized + nav)
        while True:
            moic = q2(total / invested)
            if moic not in used_moic:
                break
            # nudge realized by a cent to break a MOIC tie deterministically
            realized = q2(realized + Decimal("0.07"))
            total = q2(realized + nav)
        used_moic.add(moic)
        recs.append(
            {
                "company": name,
                "fund": fund,
                "sector": rng.choice(SECTORS),
                "geo": rng.choice(GEOS),
                "date": f"{rng.randint(2015, 2024)}-{rng.randint(1, 12):02d}",
                "invested": invested,
                "realized": realized,
                "nav": nav,
                "total": total,
                "moic": moic,
                "own": q2(Decimal(rng.uniform(5.0, 85.0))),
                "status": "Exited" if exited else "Active",
            }
        )
    return recs


def _notes(rng: random.Random, rec: dict) -> str:
    pool = [
        "Board seat held",
        "Add-on completed",
        "Refinancing under review",
        f"Follow-on of {q2(Decimal(rng.uniform(0.5, 9.0)))} in {rng.randint(2019, 2024)}",
        "Management change",
        "Exit process launched",
        "Covenant reset",
        "",
        "",
        "",
        "Buy-and-build platform",
        "ESG review complete",
    ]
    return rng.choice(pool)


# ---------------------------------------------------------------------------
# Workbook writers (6 layouts)
# ---------------------------------------------------------------------------


def _row_values(rec: dict, keys: list[str]) -> list[object]:
    # Decimal cells are written AS DECIMAL. The first version of this generator
    # wrote float(v): openpyxl serialises a float with 16 significant digits, so
    # 74.46 landed in the workbook as 74.45999999999999, and the verifier — which
    # reads the document as written — disagreed with the in-memory gold by one
    # cent on a median (measured 2026-09-02, L5_S2 Q16). The workbook bytes are
    # the truth the model and the verifier both see; the gold must be computed
    # from values that round-trip to those bytes exactly.
    return [rec[k] for k in keys]


def _write_header(ws, headers: dict, keys: list[str], multi: bool) -> None:
    ws.append([headers[k] for k in keys])
    if multi:
        for cell in ws[ws.max_row]:
            cell.alignment = Alignment(wrap_text=True)
    for cell in ws[ws.max_row]:
        cell.font = Font(bold=True)


def _subtotal(recs: list[dict], label: str, keys: list[str]) -> list[object]:
    row: list[object] = []
    for k in keys:
        if k == "company":
            row.append(label)
        elif k in ("invested", "realized", "nav", "total"):
            row.append(sum((r[k] for r in recs), Decimal(0)))
        else:
            row.append(None)
    return row


def write_workbook(
    path: Path, recs: list[dict], layout: str, rng: random.Random
) -> dict:
    """Write the workbook; return the auditor LAYOUT descriptor (sheet-query-v1
    `layout` object) that reads it back. The descriptor is what an auditor who
    owns the data room would write down about the document."""
    wb = openpyxl.Workbook()
    funds = sorted({r["fund"] for r in recs}, key=lambda f: ROMAN.index(f.split()[1]))
    multi = layout in ("L4", "L6")
    headers = dict(HEADERS_MULTI if multi else HEADERS_PLAIN)
    keys = list(COLUMN_ORDER)
    if layout == "L6":
        headers["notes"] = "Notes"
        keys = keys + ["notes"]
        for r in recs:
            r["notes"] = _notes(rng, r)
    columns_map = {k: headers[k] for k in keys if k != "notes"}
    excl = "^(Total|Subtotal|Units)$"

    if layout == "L1":
        ws = wb.active
        ws.title = "Portfolio"
        keys1 = ["fund"] + keys
        headers1 = dict(headers)
        headers1["fund"] = "Fund"
        _write_header(ws, headers1, keys1, multi)
        for r in recs:
            ws.append(_row_values(r, keys1))
        desc = {
            "sheet": "Portfolio",
            "header_match": [headers["company"], headers["moic"]],
            "columns": {**columns_map, "fund": "Fund"},
            "group_from": "column:fund",
            "exclude_first_cell": None,
            "key_column": "company",
        }

    elif layout in ("L2", "L4", "L6"):
        ws = wb.active
        ws.title = "Holdings"
        ws.append(["Portfolio Monitoring Report"])
        ws.append(
            [
                f"Quarter ended {rng.choice(['31 Mar', '30 Jun', '30 Sep', '31 Dec'])} {rng.randint(2023, 2025)}"
            ]
        )
        ws.append([])
        _write_header(ws, headers, keys, multi)
        if layout == "L6":
            ws.append(
                [
                    "Units",
                    None,
                    None,
                    None,
                    "$m",
                    "$m",
                    "$m",
                    "$m",
                    "x",
                    "%",
                    None,
                    None,
                ]
            )
        for f in funds:
            ws.append([f])
            frecs = [r for r in recs if r["fund"] == f]
            for r in frecs:
                ws.append(_row_values(r, keys))
            ws.append(_subtotal(frecs, "Subtotal", keys))
            if layout == "L6":
                ws.append([])
        ws.append(_subtotal(recs, "Total", keys))
        desc = {
            "sheet": "Holdings",
            "header_match": [headers["company"], headers["moic"]],
            "columns": columns_map,
            "group_from": r"divider:^Fund\s+[IVX]+$",
            "exclude_first_cell": excl,
            "key_column": "company",
        }

    elif layout == "L3":
        first = True
        for f in funds:
            ws = wb.active if first else wb.create_sheet()
            first = False
            ws.title = f
            ws.append([f"{f} — portfolio companies"])
            ws.append([])
            _write_header(ws, headers, keys, multi)
            for r in recs:
                if r["fund"] == f:
                    ws.append(_row_values(r, keys))
        desc = {
            "sheet": None,
            "header_match": [headers["company"], headers["moic"]],
            "columns": columns_map,
            "group_from": "sheet",
            "exclude_first_cell": excl,
            "key_column": "company",
        }

    elif layout == "L5":
        ws = wb.active
        ws.title = "Summary"
        ws.append(
            [
                "Fund",
                "# Companies",
                "Invested Capital ($m)",
                "Unrealized Value ($m)",
                "Total Value ($m)",
                "Gross MOIC (x)",
            ]
        )
        for f in funds:
            frecs = [r for r in recs if r["fund"] == f]
            inv = sum((r["invested"] for r in frecs), Decimal(0))
            nav = sum((r["nav"] for r in frecs), Decimal(0))
            tot = sum((r["total"] for r in frecs), Decimal(0))
            ws.append(
                [
                    f,
                    len(frecs),
                    inv,
                    nav,
                    tot,
                    q2(tot / inv),
                ]
            )
        ws.append(
            _subtotal(
                recs, "Total", ["company", "sector", "invested", "nav", "total", "moic"]
            )
        )
        ws2 = wb.create_sheet("Holdings")
        ws2.append(["Holdings detail"])
        ws2.append([])
        _write_header(ws2, headers, keys, multi)
        for f in funds:
            ws2.append([f])
            for r in recs:
                if r["fund"] == f:
                    ws2.append(_row_values(r, keys))
        desc = {
            "sheet": "Holdings",
            "header_match": [headers["company"], headers["moic"]],
            "columns": columns_map,
            "group_from": r"divider:^Fund\s+[IVX]+$",
            "exclude_first_cell": excl,
            "key_column": "company",
        }
    else:
        raise ValueError(layout)

    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    _canonicalize_workbook(path)
    return desc


_NUM_CELL_RE = re.compile(rb"<v>(-?\d+\.\d+(?:[eE][-+]?\d+)?)</v>")

#: Zip entries that are XML documents and so can be C14N-normalised. OOXML uses
#: `.rels` for the relationship parts; everything else in these workbooks is
#: `.xml`. A non-XML entry (an embedded image, say) must be passed through
#: untouched rather than fed to a parser.
_XML_ENTRY_SUFFIXES = (".xml", ".rels")


def _c14n(data: bytes, name: str) -> bytes:
    """Re-serialise one XML part into W3C canonical form.

    This is what makes the workbook bytes depend on the DOCUMENT rather than on
    whichever serialiser happened to write it: C14N fixes attribute order,
    namespace declaration placement, and empty-element form, all of which carry
    no meaning and all of which the two openpyxl writers disagree about.

    These parts carry no XML declaration (openpyxl writes none), so C14N's
    dropping of one is a no-op here rather than a format change.

    REFUSES a part carrying a DTD or entity declaration, and that refusal is
    load-bearing rather than defensive. The verifier's reader
    (`sheet_query._guard_xml`) rejects a workbook whose RAW bytes contain
    `<!DOCTYPE` or `<!ENTITY` — a guard added 2026-09-02 after an adversarial
    pass got an entity expanded into a cell past a prefix-only scan. C14N
    deletes the internal subset and inlines the expansion, so canonicalising
    such a part would LAUNDER it: the bytes the verifier finally sees no longer
    contain the thing its guard looks for. Found by the red-team lens on
    2026-09-03, which built two workbooks differing only in an entity-expanded
    cell and canonicalised them to the same digest while the verifier's own
    reader accepted one and refused the other. The generator never emits a DTD,
    so this raises rather than strips: silently normalising it away is precisely
    the failure mode.
    """
    import io
    from xml.etree import ElementTree as ET

    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ValueError(
            f"{name}: refusing to canonicalise a part carrying a DTD/entity "
            "declaration — C14N would inline it and hide it from the "
            "verifier's own byte-level guard (sheet_query._guard_xml)"
        )
    out = io.StringIO()
    ET.canonicalize(xml_data=data.decode("utf-8"), out=out)
    return out.getvalue().encode("utf-8")


def _canonicalize_workbook(path: Path) -> None:
    """Make the generated workbook byte-identical across environments.

    The auditor's spec pins sha256(workbook), so the generator has to be a
    function of its seed and nothing else. Three sources of drift are removed
    here, all PRODUCER-side, on the producer's own artifact; the verifier knows
    nothing about any of it.

    1. **Number form.** openpyxl serialises EVERY numeric cell — float or
       Decimal — with 16 significant digits, so Decimal("74.46") lands in the
       file as 74.45999999999999. The verifier reads the document as written and
       was right to; the gold was wrong by one cent on a median (measured
       2026-09-02, L5_S2 Q16). The workbook bytes are what the model and the
       verifier both see, so the bytes must carry the value the generator
       intends.

    2. **Wall-clock stamps.** openpyxl writes created/modified times into
       docProps/core.xml and the current mtime onto every zip entry.

    3. **Serialiser choice** — the one that made this pilot machine-dependent.
       `openpyxl.LXML` is True when lxml is importable and False otherwise, and
       the two writers emit different bytes for the same workbook: `<tag/>` vs
       `<tag />`, different namespace-declaration placement, different attribute
       order. Measured 2026-09-03 on openpyxl 3.1.5: seven of the nine zip
       entries differed, so the same seed produced a different sha256 and the
       pinned spec rejected the honest bundle with PINNED_INPUT_MISMATCH. It had
       always passed in-house only because lxml happened to be installed.
       C14N-normalising each XML part makes the output a function of the
       document, so both writers land on the same bytes.

    Canonicalisation is safe here because it removes degrees of freedom that
    carry no content: any change to a cell still changes the canonical form, and
    the auditor still pins the exact bytes the bundle ships. The control is
    `test_a_content_edit_still_moves_the_workbook_digest`, which edits a cell and
    requires the digest to move. It is NOT a general claim that C14N preserves
    OOXML semantics — it does not (it drops comments, and it drops namespace
    declarations that are not visibly utilised, which would strand an
    `mc:Ignorable` prefix in a workbook this generator did not write). The claim
    is scoped to this generator's own output, and `_c14n` refuses outright the
    one case where normalising would hide something from the verifier.
    """
    import zipfile

    src = zipfile.ZipFile(path)
    entries = [(info, src.read(info.filename)) for info in src.infolist()]
    src.close()
    fixed_dt = (2026, 9, 2, 0, 0, 0)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info, data in entries:
            if info.filename.startswith("xl/worksheets/") and info.filename.endswith(
                ".xml"
            ):
                data = _NUM_CELL_RE.sub(
                    lambda m: b"<v>" + repr(float(m.group(1))).encode() + b"</v>", data
                )
            if info.filename == "docProps/core.xml":
                data = re.sub(
                    rb"(<dcterms:(?:created|modified)[^>]*>)[^<]*(</dcterms:(?:created|modified)>)",
                    rb"\g<1>2026-09-02T00:00:00Z\g<2>",
                    data,
                )
                # `<dc:creator>openpyxl</dc:creator>`. The bare tool name carries
                # no version today and is stable across the versions measured,
                # but it is the same kind of value as app.xml's — if openpyxl
                # ever appends one, the pinned digest silently goes back to
                # being a digest of the build environment. Neutralised so the
                # invariant is "no part names the toolchain" rather than "no
                # part names a version we happened to check".
                data = re.sub(
                    rb"(<dc:creator[^>]*>)[^<]*(</dc:creator>)",
                    rb"\g<1>finsheet_style_minimal generator\g<2>",
                    data,
                )
            if info.filename == "docProps/app.xml":
                # openpyxl stamps its OWN VERSION in here — the shipped file
                # said "Microsoft Excel Compatible / Openpyxl 3.1.5". C14N
                # normalises how a part is serialised, never what it contains,
                # so it cannot touch this, and the pinned digest was therefore
                # still a digest of the build environment: measured 2026-09-03,
                # openpyxl 3.1.2 and 3.0.10 each produce a different sha256 and
                # PINNED_INPUT_MISMATCH, with app.xml the ONLY differing entry
                # between 3.1.5 and 3.1.2. Since the extra declares openpyxl>=3.1
                # unpinned, that is the same defect this function exists to fix,
                # one variable over. No reader in this pilot consumes app.xml.
                data = re.sub(
                    rb"(<Application>)[^<]*(</Application>)",
                    rb"\g<1>finsheet_style_minimal generator\g<2>",
                    data,
                )
                data = re.sub(
                    rb"(<AppVersion>)[^<]*(</AppVersion>)", rb"\g<1>1.0\g<2>", data
                )
            if info.filename.endswith(_XML_ENTRY_SUFFIXES):
                data = _c14n(data, info.filename)
            zi = zipfile.ZipInfo(info.filename, date_time=fixed_dt)
            zi.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(zi, data)


# ---------------------------------------------------------------------------
# Questions: 16 templates, gold by the generator's own arithmetic
# ---------------------------------------------------------------------------


def _fmt(d: Decimal) -> float:
    return float(q2(d))


def _median(xs: list[Decimal]) -> Decimal:
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def make_questions(
    rng: random.Random, recs: list[dict], layout_desc: dict
) -> list[dict]:
    """Instantiate the 16 templates. Each question carries its gold (generator
    arithmetic), the auditor query (sheet-query-v1), and `answer_kind` in
    {number, count, string, list} which selects the comparator."""
    funds = sorted({r["fund"] for r in recs}, key=lambda f: ROMAN.index(f.split()[1]))
    hdr = layout_desc["columns"]
    fund_col = "__group__"

    def by_fund(f):
        return [r for r in recs if r["fund"] == f]

    def base(op, **kw):
        d = {"schema": "sheet-query-v1", "layout": layout_desc, "round": 2, "op": op}
        d.update(kw)
        return d

    def flt(col, val, op="eq"):
        return {"column": col, "op": op, "value": val}

    qs: list[dict] = []
    c1, c2, c3, c4 = rng.sample(recs, 4)
    fA = rng.choice(funds)
    fB = rng.choice(funds)
    fC = rng.choice(funds)
    fD = rng.choice(funds)
    fE = rng.choice(funds)
    present_sectors = sorted({r["sector"] for r in recs})
    sA = rng.choice(present_sectors)
    sB = rng.choice(present_sectors)
    present_geos = sorted({r["geo"] for r in recs})
    gA = rng.choice(present_geos)
    moics = sorted(r["moic"] for r in recs)
    # threshold strictly between two MOICs so 1..n-1 companies match
    ti = rng.randint(0, len(moics) - 2)
    t = q2((moics[ti] + moics[ti + 1]) / 2)
    if t == moics[ti] or t == moics[ti + 1]:
        t = moics[ti] + Decimal("0.005")

    # Low — lookups
    qs.append(
        {
            "qid": "Q01",
            "tier": "low",
            "answer_kind": "number",
            "text": f"What is the unrealized value (NAV, $m) of {c1['company']}?",
            "gold": _fmt(c1["nav"]),
            "query": base(
                "lookup", column="nav", filters=[flt("company", c1["company"])]
            ),
        }
    )
    qs.append(
        {
            "qid": "Q02",
            "tier": "low",
            "answer_kind": "string",
            "text": f"What sector is {c2['company']} in?",
            "gold": norm(c2["sector"]),
            "query": base(
                "lookup", column="sector", filters=[flt("company", c2["company"])]
            ),
        }
    )
    qs.append(
        {
            "qid": "Q03",
            "tier": "low",
            "answer_kind": "number",
            "text": f"How much invested capital ($m) does the portfolio hold in {c3['company']}?",
            "gold": _fmt(c3["invested"]),
            "query": base(
                "lookup", column="invested", filters=[flt("company", c3["company"])]
            ),
        }
    )
    qs.append(
        {
            "qid": "Q04",
            "tier": "low",
            "answer_kind": "number",
            "text": f"What is the MOIC (x) of {c4['company']}?",
            "gold": _fmt(c4["moic"]),
            "query": base(
                "lookup", column="moic", filters=[flt("company", c4["company"])]
            ),
        }
    )
    # Medium — list / filter / count
    qs.append(
        {
            "qid": "Q05",
            "tier": "medium",
            "answer_kind": "list",
            "text": f"List the portfolio companies in {fA}.",
            "gold": sorted({norm(r["company"]) for r in by_fund(fA)}),
            "query": base("list", **{"return": "company"}, filters=[flt(fund_col, fA)]),
        }
    )
    qs.append(
        {
            "qid": "Q06",
            "tier": "medium",
            "answer_kind": "list",
            "text": f"List the portfolio companies in the {sA} sector (all funds).",
            "gold": sorted({norm(r["company"]) for r in recs if r["sector"] == sA}),
            "query": base("list", **{"return": "company"}, filters=[flt("sector", sA)]),
        }
    )
    qs.append(
        {
            "qid": "Q07",
            "tier": "medium",
            "answer_kind": "count",
            "text": f"How many companies in {fB} have status Exited?",
            "gold": sum(1 for r in by_fund(fB) if r["status"] == "Exited"),
            "query": base(
                "count", filters=[flt(fund_col, fB), flt("status", "Exited")]
            ),
        }
    )
    qs.append(
        {
            "qid": "Q08",
            "tier": "medium",
            "answer_kind": "count",
            "text": f"How many portfolio companies are in {gA} (all funds)?",
            "gold": sum(1 for r in recs if r["geo"] == gA),
            "query": base("count", filters=[flt("geo", gA)]),
        }
    )
    qs.append(
        {
            "qid": "Q09",
            "tier": "medium",
            "answer_kind": "list",
            "text": f"List the companies with a MOIC strictly greater than {t}x (all funds).",
            "gold": sorted({norm(r["company"]) for r in recs if r["moic"] > t}),
            "query": base(
                "list", **{"return": "company"}, filters=[flt("moic", float(t), "gt")]
            ),
        }
    )
    # High — aggregate / sort
    qs.append(
        {
            "qid": "Q10",
            "tier": "high",
            "answer_kind": "number",
            "text": f"What is the total unrealized value (NAV, $m) of {fC}? Answer to 2 decimals.",
            "gold": _fmt(sum((r["nav"] for r in by_fund(fC)), Decimal(0))),
            "query": base("sum", column="nav", filters=[flt(fund_col, fC)]),
        }
    )
    qs.append(
        {
            "qid": "Q11",
            "tier": "high",
            "answer_kind": "number",
            "text": f"What is the total invested capital ($m) in the {sB} sector across all funds? Answer to 2 decimals.",
            "gold": _fmt(
                sum((r["invested"] for r in recs if r["sector"] == sB), Decimal(0))
            ),
            "query": base("sum", column="invested", filters=[flt("sector", sB)]),
        }
    )
    top = max(by_fund(fD), key=lambda r: r["moic"])
    qs.append(
        {
            "qid": "Q12",
            "tier": "high",
            "answer_kind": "string",
            "text": f"Which company in {fD} has the highest MOIC?",
            "gold": norm(top["company"]),
            "query": base(
                "argmax",
                column="moic",
                **{"return": "company"},
                filters=[flt(fund_col, fD)],
            ),
        }
    )
    top3 = sorted(recs, key=lambda r: r["nav"], reverse=True)[:3]
    qs.append(
        {
            "qid": "Q13",
            "tier": "high",
            "answer_kind": "list",
            "text": "Which three companies have the largest unrealized value (NAV) across all funds?",
            "gold": sorted(norm(r["company"]) for r in top3),
            "query": base("topk", column="nav", k=3, **{"return": "company"}),
        }
    )
    fe = by_fund(fE)
    qs.append(
        {
            "qid": "Q14",
            "tier": "high",
            "answer_kind": "number",
            "text": f"What is the average MOIC (x) of the companies in {fE}? Answer to 2 decimals.",
            "gold": _fmt(sum((r["moic"] for r in fe), Decimal(0)) / len(fe)),
            "query": base("mean", column="moic", filters=[flt(fund_col, fE)]),
        }
    )
    qs.append(
        {
            "qid": "Q15",
            "tier": "high",
            "answer_kind": "number",
            "text": "What is the total realized value ($m) across all funds? Answer to 2 decimals.",
            "gold": _fmt(sum((r["realized"] for r in recs), Decimal(0))),
            "query": base("sum", column="realized"),
        }
    )
    # Very high — median
    fm = rng.choice(funds)
    qs.append(
        {
            "qid": "Q16",
            "tier": "very_high",
            "answer_kind": "number",
            "text": f"What is the median unrealized value (NAV, $m) of the companies in {fm}? Answer to 2 decimals.",
            "gold": _fmt(_median([r["nav"] for r in by_fund(fm)])),
            "query": base("median", column="nav", filters=[flt(fund_col, fm)]),
        }
    )
    for q in qs:
        q["template"] = q["qid"]
    # Keep the header labels the model will see, for the prompt's column glossary.
    for q in qs:
        q["column_glossary"] = {
            "NAV / unrealized value": hdr["nav"],
            "invested capital": hdr["invested"],
            "realized value": hdr["realized"],
            "MOIC": hdr["moic"],
            "sector": hdr["sector"],
            "geography": hdr["geo"],
            "status": hdr["status"],
            "company": hdr["company"],
        }
    return qs


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build_one(file_id: str, out_dir: Path) -> tuple[Path, list[dict], list[dict]]:
    """Build ONE workbook + its 16 questions, deterministically. Returns
    (workbook_path, records, questions). Used by build_set and by the pilot's
    _build_bundle.py demo, which needs the producer's own records to state an
    honest derivation."""
    layout, size = file_id.split("_")
    if layout not in LAYOUTS or size not in SIZES:
        raise ValueError(f"unknown file_id {file_id!r}")
    li = LAYOUTS.index(layout)
    si = list(SIZES).index(size)
    n_c, n_f = SIZES[size]
    rng = random.Random(BASE_SEED + li * 100 + si)
    recs = synthesize(rng, n_c, n_f)
    path = out_dir / "workbooks" / f"{file_id}.xlsx"
    desc = write_workbook(path, recs, layout, rng)
    qs = make_questions(rng, recs, desc)
    for q in qs:
        q["file_id"] = file_id
    return path, recs, qs


def build_set(out_dir: Path, only: str | None = None) -> dict:
    out_dir = out_dir.resolve()
    (out_dir / "workbooks").mkdir(parents=True, exist_ok=True)
    manifest: dict = {}
    questions: list[dict] = []
    for layout in LAYOUTS:
        for size, (n_c, n_f) in SIZES.items():
            file_id = f"{layout}_{size}"
            if only and file_id != only:
                continue
            path, _recs, qs = build_one(file_id, out_dir)
            questions.extend(qs)
            manifest[file_id] = {
                "sha256": sha256_file(path),
                "layout": layout,
                "size": size,
                "companies": n_c,
                "funds": n_f,
                "sheets": len(openpyxl.load_workbook(path, read_only=True).sheetnames),
            }
    (out_dir / "questions.json").write_text(
        json.dumps(questions, indent=1, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    (out_dir / "set_manifest.json").write_text(
        json.dumps(
            {"set_version": SET_VERSION, "base_seed": BASE_SEED, "files": manifest},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "files": len(manifest),
        "questions": len(questions),
        "out_dir": str(out_dir),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate the FinSheet-style set (producer side)"
    )
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--only", default=None, help="one file_id, e.g. L2_S1")
    args = ap.parse_args()
    info = build_set(args.out_dir, args.only)
    print(json.dumps(info))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
