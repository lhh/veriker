"""sheet_query — verifier-side re-derivation over an .xlsx workbook.

Two primitives, one file, one stdlib workbook reader. Both read the workbook
from the FIXED bundle path ``data/workbook.xlsx`` and parse it here, in
verifier-distribution code: the bundle carries the workbook BYTES, never a
table the producer already extracted. That is the split FinSheet-Bench
(arXiv 2603.07316) asks for — "separate document understanding from
deterministic computation" — placed on the verifier's side of the line.

``sheet_query_recompute`` (Arm A, the semantic ceiling)
    Reads the AUDITOR's question as a closed-world query
    (``inputs/query.json``, schema ``sheet-query-v1``) and recomputes the
    answer from the workbook. The query file is producer-visible but
    auditor-authored: the anchored spec pins its sha256 through
    ``pinned_inputs``, so a producer who answers a different question than
    the one asked changes a pinned sha and dispatch refuses. The query
    carries the auditor's reading of the document (which sheet, which header
    cells, how fund membership is encoded) because the auditor owns the data
    room; the primitive owns the arithmetic.

``sheet_derivation_replay`` (Arm B, the spec-free number)
    Reads the PRODUCER's own stated derivation (``inputs/derivation.json``,
    schema ``sheet-derivation-v1``: an operation and the operand values it
    says it used), replays the operation, and checks that every operand
    occurs somewhere in the workbook. The auditor holds nothing but the
    workbook. This catches an answer that disagrees with its own working and
    an operand that was never in the sheet; it cannot catch a wrong
    selection computed correctly, and says so in its scope limits.

Value conventions shared by both (the comparator sees these):
  - numbers: Python float of a Decimal rounded HALF_UP to ``round`` places
    (default 2) — bind with ``scalar_epsilon``;
  - counts: int — bind with ``exact``;
  - strings: casefolded, whitespace-collapsed — bind with ``exact``;
  - lists of strings: sorted, de-duplicated, normalized — bind with ``set``;
  - a determinate refusal (ambiguous lookup, empty aggregate, missing
    operand): a dict ``{"kind": "refused" | "operand_not_in_sheet", ...}``,
    which no scalar/exact/set claim can equal — a REJECT with the reason in
    the comparator detail, never a crash and never a pass.

Stdlib-only (§C5 core verify() path): zipfile + xml.etree + decimal.
"""

from __future__ import annotations

import re
import secrets
import zipfile
import zlib
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from xml.etree import ElementTree as ET

from ...admission import InputInadmissible, admit_bytes
from ...strict_json import strict_json_loads
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive

WORKBOOK_REL = "data/workbook.xlsx"
QUERY_REL = "inputs/query.json"
DERIVATION_REL = "inputs/derivation.json"

QUERY_SCHEMA = "sheet-query-v1"
DERIVATION_SCHEMA = "sheet-derivation-v1"

# Admission bounds on the workbook zip: an .xlsx is a zip, and a zip can lie
# about its size. Bounded BEFORE any XML is parsed.
_MAX_ZIP_ENTRIES = 512
_MAX_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 128 * 1024 * 1024
# Grid bounds. Excel's own sheet limits are 1,048,576 rows x 16,384 columns; a
# cell reference past either is not a workbook this reader admits, and the
# materialised grid is height x width regardless of how many cells are
# present, so the PRODUCT is capped too (adversarial pass 2026-09-02: one
# 6 KB file with a single cell at row 20,000,000 cost 4.1 GB).
_MAX_ROWS = 1_048_576
_MAX_COLS = 16_384
_MAX_GRID_CELLS = 4_000_000

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_DOCREL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

_OPS = ("lookup", "list", "count", "sum", "mean", "median", "argmax", "topk")
_FILTER_OPS = ("eq", "ne", "gt", "gte", "lt", "lte")
_GROUP_KINDS = ("column", "divider", "sheet")

_WS_RE = re.compile(r"\s+")
_CELL_RE = re.compile(r"\A([A-Z]{1,3})(\d+)\Z")


# ---------------------------------------------------------------------------
# Normalisation helpers (the contract's normal forms)
# ---------------------------------------------------------------------------


def norm_text(s: object) -> str:
    """Casefold + collapse whitespace (newlines in multi-line headers included)."""
    return _WS_RE.sub(" ", str(s)).strip().casefold()


def round_half_up(d: Decimal, places: int) -> Decimal:
    q = Decimal(1).scaleb(-places)
    return d.quantize(q, rounding=ROUND_HALF_UP)


def _to_decimal(v: object) -> Decimal | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, Decimal):
        return v
    if isinstance(v, int):
        return Decimal(v)
    if isinstance(v, float):
        d = Decimal(repr(v))
        return d if d.is_finite() else None
    if isinstance(v, str):
        t = v.strip().replace(",", "")
        if not t:
            return None
        try:
            d = Decimal(t)
        except InvalidOperation:
            return None
        return d if (d.is_finite() and abs(d.adjusted()) <= 308) else None
    return None


def _refusal(kind: str, **fields: object) -> dict:
    """A determinate refusal as a VALUE the comparator cannot be made to equal.

    The refusal carries a per-call random nonce. Without it the refusal was a
    plain dict, and a producer who writes that same dict as its claimed value
    equals it under `exact` (`a == b`) and `set` (dict keys) -- measured
    2026-09-02: Arm B nullified with `outputs/answer_consistency.json` set to
    `{"kind": "refused", ...}` and an empty derivation, exit 0. A claim written
    before verification cannot contain a nonce drawn during it.
    """
    tok = secrets.token_hex(16)
    # The nonce is a KEY as well as a value: `set` iterates a dict's KEYS, so a
    # nonce held only as a value was still forgeable through the list kind —
    # the regression test for this very fix caught it (["kind", "reason",
    # "nonce"] compared equal to the refusal's key set at exit 0).
    out: dict = {"kind": kind, "nonce": tok, f"nonce:{tok}": kind}
    out.update(fields)
    return out


# ---------------------------------------------------------------------------
# Stdlib .xlsx reader
# ---------------------------------------------------------------------------


class WorkbookUnreadable(ValueError):
    """The bytes at data/workbook.xlsx are not a workbook this reader admits."""


def _col_index(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _guard_xml(raw: bytes, name: str) -> None:
    # The WHOLE entry, not a prefix: XML admits any amount of whitespace and
    # comments before <!DOCTYPE>, and the first version scanned 4096 bytes
    # (adversarial pass 2026-09-02: 5000 spaces then a DOCTYPE with an entity
    # expanded into a cell, verify exit 0). The bytes are already in memory.
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise WorkbookUnreadable(f"{name}: DTD/entity declarations are refused")


def _read_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    try:
        raw = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    _guard_xml(raw, "sharedStrings.xml")
    root = ET.fromstring(raw)
    out: list[str] = []
    for si in root.findall(f"{{{_NS_MAIN}}}si"):
        parts = [t.text or "" for t in si.iter(f"{{{_NS_MAIN}}}t")]
        out.append("".join(parts))
    return out


def _sheet_targets(zf: zipfile.ZipFile) -> list[tuple[str, str]]:
    """[(sheet_name, zip_path)] in workbook order."""
    raw_wb = zf.read("xl/workbook.xml")
    _guard_xml(raw_wb, "workbook.xml")
    wb = ET.fromstring(raw_wb)
    raw_rels = zf.read("xl/_rels/workbook.xml.rels")
    _guard_xml(raw_rels, "workbook.xml.rels")
    rels = ET.fromstring(raw_rels)
    rid_to_target: dict[str, str] = {}
    for rel in rels.findall(f"{{{_NS_REL}}}Relationship"):
        target = rel.get("Target", "")
        if target.startswith("/"):
            target = target[1:]
        elif not target.startswith("xl/"):
            target = "xl/" + target
        rid_to_target[rel.get("Id", "")] = target
    out: list[tuple[str, str]] = []
    sheets = wb.find(f"{{{_NS_MAIN}}}sheets")
    if sheets is None:
        raise WorkbookUnreadable("workbook.xml has no <sheets>")
    for sh in sheets.findall(f"{{{_NS_MAIN}}}sheet"):
        name = sh.get("name", "")
        rid = sh.get(f"{{{_NS_DOCREL}}}id", "")
        target = rid_to_target.get(rid)
        if not name or not target:
            raise WorkbookUnreadable(f"sheet {name!r} has no resolvable target")
        out.append((name, target))
    return out


def _read_sheet(
    zf: zipfile.ZipFile, target: str, shared: list[str]
) -> list[list[object]]:
    raw = zf.read(target)
    _guard_xml(raw, target)
    root = ET.fromstring(raw)
    rows: dict[int, dict[int, object]] = {}
    width = 0
    height = 0
    for c in root.iter(f"{{{_NS_MAIN}}}c"):
        ref = c.get("r", "")
        m = _CELL_RE.match(ref)
        if not m:
            raise WorkbookUnreadable(f"{target}: cell reference {ref!r} unparseable")
        ci = _col_index(m.group(1))
        ri = int(m.group(2)) - 1
        if ri < 0 or ri >= _MAX_ROWS or ci >= _MAX_COLS:
            raise WorkbookUnreadable(
                f"{target}: cell reference {ref!r} outside the admitted grid "
                f"(rows 1..{_MAX_ROWS}, columns A..{_MAX_COLS})"
            )
        t = c.get("t", "n")
        v_el = c.find(f"{{{_NS_MAIN}}}v")
        value: object = None
        if t == "s":
            if v_el is None or v_el.text is None:
                value = None
            else:
                idx = int(v_el.text)
                if idx < 0 or idx >= len(shared):
                    raise WorkbookUnreadable(
                        f"{target}: shared string index {idx} out of range"
                    )
                value = shared[idx]
        elif t == "inlineStr":
            is_el = c.find(f"{{{_NS_MAIN}}}is")
            value = "".join(
                (x.text or "")
                for x in (is_el.iter(f"{{{_NS_MAIN}}}t") if is_el is not None else [])
            )
        elif t == "str":
            value = v_el.text if v_el is not None else None
        elif t == "b":
            value = "TRUE" if (v_el is not None and v_el.text == "1") else "FALSE"
        elif t in ("n", "d", "e"):
            if v_el is None or v_el.text is None:
                value = None
            else:
                try:
                    value = Decimal(v_el.text)
                except InvalidOperation:
                    value = v_el.text
                else:
                    # Finite AND within the range a spreadsheet double can hold:
                    # Decimal("1e999999") is finite to Python and overflows the
                    # first quantize downstream.
                    if not value.is_finite() or abs(value.adjusted()) > 308:
                        raise WorkbookUnreadable(
                            f"{target}: numeric cell {ref} = {v_el.text!r} is non-finite "
                            "or outside the double range"
                        )
        else:
            raise WorkbookUnreadable(f"{target}: unknown cell type {t!r}")
        if value is None:
            continue
        rows.setdefault(ri, {})[ci] = value
        width = max(width, ci + 1)
        height = max(height, ri + 1)
        if height * width > _MAX_GRID_CELLS:
            raise WorkbookUnreadable(
                f"{target}: grid {height} x {width} exceeds {_MAX_GRID_CELLS} cells"
            )
    grid: list[list[object]] = []
    for r in range(height):
        row = rows.get(r, {})
        grid.append([row.get(c) for c in range(width)])
    return grid


def read_workbook(path: Path) -> dict[str, list[list[object]]]:
    """{sheet_name: grid} — grid is a rectangular list of rows; cells are
    str / Decimal / None. Bounded, DTD-refusing, stdlib only."""
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise WorkbookUnreadable(f"not a zip container: {exc}") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > _MAX_ZIP_ENTRIES:
            raise WorkbookUnreadable(
                f"zip has {len(infos)} entries > {_MAX_ZIP_ENTRIES}"
            )
        total = 0
        for info in infos:
            if info.file_size > _MAX_ENTRY_BYTES:
                raise WorkbookUnreadable(
                    f"{info.filename}: {info.file_size} bytes > entry cap"
                )
            total += info.file_size
        if total > _MAX_TOTAL_BYTES:
            raise WorkbookUnreadable(f"zip inflates to {total} bytes > total cap")
        try:
            shared = _read_shared_strings(zf)
            out: dict[str, list[list[object]]] = {}
            for name, target in _sheet_targets(zf):
                if name in out:
                    raise WorkbookUnreadable(f"duplicate sheet name {name!r}")
                out[name] = _read_sheet(zf, target, shared)
        except (
            KeyError,
            ET.ParseError,
            ValueError,
            zipfile.BadZipFile,
            zlib.error,
            MemoryError,
            OverflowError,
        ) as exc:
            if isinstance(exc, WorkbookUnreadable):
                raise
            raise WorkbookUnreadable(
                f"malformed workbook: {type(exc).__name__}: {exc}"
            ) from exc
    if not out:
        raise WorkbookUnreadable("workbook has no sheets")
    return out


# ---------------------------------------------------------------------------
# Table extraction under an auditor layout (sheet-query-v1)
# ---------------------------------------------------------------------------


class QueryRefused(ValueError):
    """A determinate refusal: the query cannot be answered from this workbook
    (ambiguous lookup, header not found, empty aggregate). Surfaced as a
    value, so the comparator rejects with the reason on the face."""


def _find_header(
    grid: list[list[object]], header_match: list[str]
) -> tuple[int, dict[str, int]] | None:
    wanted = [norm_text(h) for h in header_match]
    for ri, row in enumerate(grid):
        cells = {norm_text(c): ci for ci, c in enumerate(row) if c is not None}
        if all(w in cells for w in wanted):
            return ri, cells
    return None


def _first_nonempty(row: list[object]) -> object:
    for c in row:
        if c is not None and str(c).strip() != "":
            return c
    return None


def _nonempty_count(row: list[object]) -> int:
    return sum(1 for c in row if c is not None and str(c).strip() != "")


def extract_rows(
    workbook: dict[str, list[list[object]]], layout: dict
) -> list[dict[str, object]]:
    """Rows of {logical_column: cell_value, "__group__": fund_label}.

    layout:
      sheet         str | None   — restrict to one sheet; None = every sheet
                                   whose header matches (group_from=sheet needs
                                   None or a list handled per sheet)
      header_match  [str]        — header texts that identify the header row
      columns       {logical: header_text} — logical names the query uses
      group_from    "column:<logical>" | "divider:<regex>" | "sheet"
      exclude_first_cell  regex | None — skip rows whose first non-empty
                                   cell matches (Total, Subtotal, Units ...)
      key_column    logical     — a row is data only if this cell is non-empty
    """
    if not isinstance(layout, dict):
        raise QueryRefused("layout must be an object")
    header_match = layout.get("header_match")
    columns = layout.get("columns")
    group_from = layout.get("group_from")
    key_column = layout.get("key_column")
    sheet_sel = layout.get("sheet")
    excl = layout.get("exclude_first_cell")
    if not isinstance(header_match, list) or not header_match:
        raise QueryRefused("layout.header_match must be a non-empty list")
    if not isinstance(columns, dict) or not columns:
        raise QueryRefused("layout.columns must be a non-empty object")
    if (
        not isinstance(group_from, str)
        or ":" not in group_from
        and group_from != "sheet"
    ):
        raise QueryRefused(
            "layout.group_from must be column:<logical>|divider:<regex>|sheet"
        )
    if not isinstance(key_column, str) or key_column not in columns:
        raise QueryRefused("layout.key_column must name a logical column")
    gkind, _, garg = group_from.partition(":")
    if gkind not in _GROUP_KINDS:
        raise QueryRefused(f"layout.group_from kind {gkind!r} unknown")
    # Regexes see the cell's COLLAPSED text (whitespace collapsed, stripped,
    # case-insensitive), the same normal form the contract uses for header
    # matching -- 'Subtotal ' and 'SUBTOTAL' were summed as companies when the
    # regex saw the raw cell (adversarial pass 2026-09-02).
    excl_re = re.compile(excl, re.IGNORECASE) if isinstance(excl, str) and excl else None
    div_re = re.compile(garg, re.IGNORECASE) if gkind == "divider" else None
    if gkind == "column" and garg not in columns:
        raise QueryRefused("group_from column must be a logical column")

    sheets = [
        (n, g) for n, g in workbook.items() if sheet_sel is None or n == sheet_sel
    ]
    if not sheets:
        raise QueryRefused(f"sheet {sheet_sel!r} not in workbook")
    out: list[dict[str, object]] = []
    matched_any = False
    for sname, grid in sheets:
        found = _find_header(grid, header_match)
        if found is None:
            if sheet_sel is not None:
                raise QueryRefused(
                    f"header {header_match!r} not found on sheet {sname!r}"
                )
            continue
        matched_any = True
        hrow, cells = found
        col_idx: dict[str, int] = {}
        for logical, header_text in columns.items():
            ci = cells.get(norm_text(header_text))
            if ci is None:
                raise QueryRefused(
                    f"column {logical!r} ({header_text!r}) not in header of {sname!r}"
                )
            col_idx[logical] = ci
        group: object = sname if gkind == "sheet" else None
        for row in grid[hrow + 1 :]:
            if _nonempty_count(row) == 0:
                continue
            first = _first_nonempty(row)
            if (
                div_re is not None
                and _nonempty_count(row) == 1
                and first is not None
                and div_re.search(_WS_RE.sub(" ", str(first)).strip())
            ):
                group = _WS_RE.sub(" ", str(first)).strip()
                continue
            if (
                excl_re is not None
                and first is not None
                and excl_re.search(_WS_RE.sub(" ", str(first)).strip())
            ):
                continue
            key_val = (
                row[col_idx[key_column]] if col_idx[key_column] < len(row) else None
            )
            if key_val is None or str(key_val).strip() == "":
                continue
            rec: dict[str, object] = {}
            for logical, ci in col_idx.items():
                rec[logical] = row[ci] if ci < len(row) else None
            if gkind == "column":
                rec["__group__"] = rec.get(garg)
            else:
                rec["__group__"] = group
            out.append(rec)
    if not matched_any:
        raise QueryRefused(f"header {header_match!r} not found on any sheet")
    return out


def _cell_matches(cell: object, op: str, value: object) -> bool:
    if op in ("eq", "ne"):
        cd, vd = _to_decimal(cell), _to_decimal(value)
        if cd is not None and vd is not None:
            eq = cd == vd
        else:
            eq = norm_text(cell if cell is not None else "") == norm_text(
                value if value is not None else ""
            )
        return eq if op == "eq" else not eq
    cd, vd = _to_decimal(cell), _to_decimal(value)
    if cd is None or vd is None:
        return False
    if op == "gt":
        return cd > vd
    if op == "gte":
        return cd >= vd
    if op == "lt":
        return cd < vd
    if op == "lte":
        return cd <= vd
    raise QueryRefused(f"filter op {op!r} unknown")


def _apply_filters(
    rows: list[dict[str, object]], filters: object
) -> list[dict[str, object]]:
    if filters is None:
        return rows
    if not isinstance(filters, list):
        raise QueryRefused("filters must be a list")
    kept = rows
    for f in filters:
        if not isinstance(f, dict):
            raise QueryRefused("filter must be an object")
        col = f.get("column")
        op = f.get("op", "eq")
        if op not in _FILTER_OPS:
            raise QueryRefused(f"filter op {op!r} not in {_FILTER_OPS}")
        if col == "__group__":
            key = "__group__"
        elif isinstance(col, str):
            key = col
        else:
            raise QueryRefused("filter.column must be a string")
        if "value" not in f:
            raise QueryRefused("filter needs a value")
        val = f["value"]
        kept = [r for r in kept if key in r and _cell_matches(r[key], op, val)]
    return kept


def _numeric_column(rows: list[dict[str, object]], column: str) -> list[Decimal]:
    out: list[Decimal] = []
    for r in rows:
        d = _to_decimal(r.get(column))
        if d is None:
            raise QueryRefused(
                f"non-numeric cell in column {column!r}: {r.get(column)!r}"
            )
        out.append(d)
    return out


def _median(xs: list[Decimal]) -> Decimal:
    s = sorted(xs)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    return (s[n // 2 - 1] + s[n // 2]) / 2


def _emit_number(d: Decimal, places: int) -> float:
    return float(round_half_up(d, places))


def _emit_string(v: object) -> str:
    d = _to_decimal(v)
    if d is not None and not isinstance(v, str):
        return str(d.normalize())
    return norm_text(v if v is not None else "")


def evaluate_query(workbook: dict[str, list[list[object]]], query: dict) -> object:
    """Answer a sheet-query-v1 query against a parsed workbook. Raises
    QueryRefused on a determinate refusal."""
    if not isinstance(query, dict) or query.get("schema") != QUERY_SCHEMA:
        raise QueryRefused(f"query schema must be {QUERY_SCHEMA!r}")
    op = query.get("op")
    if op not in _OPS:
        raise QueryRefused(f"op {op!r} not in {_OPS}")
    places = query.get("round", 2)
    if (
        not isinstance(places, int)
        or isinstance(places, bool)
        or places < 0
        or places > 6
    ):
        raise QueryRefused("round must be an int in 0..6")
    rows = extract_rows(workbook, query.get("layout"))
    rows = _apply_filters(rows, query.get("filters"))
    column = query.get("column")
    ret = query.get("return")

    if op == "lookup":
        if not isinstance(column, str):
            raise QueryRefused("lookup needs column")
        if len(rows) != 1:
            raise QueryRefused(f"lookup matched {len(rows)} rows, need exactly 1")
        v = rows[0].get(column)
        d = _to_decimal(v)
        if d is not None and not isinstance(v, str):
            return _emit_number(d, places)
        return _emit_string(v)
    if op == "list":
        if not isinstance(ret, str):
            raise QueryRefused("list needs return")
        return sorted({_emit_string(r.get(ret)) for r in rows})
    if op == "count":
        return len(rows)
    if op in ("sum", "mean", "median"):
        if not isinstance(column, str):
            raise QueryRefused(f"{op} needs column")
        xs = _numeric_column(rows, column)
        if not xs:
            raise QueryRefused(f"{op} over zero rows")
        if op == "sum":
            return _emit_number(sum(xs, Decimal(0)), places)
        if op == "mean":
            return _emit_number(sum(xs, Decimal(0)) / len(xs), places)
        return _emit_number(_median(xs), places)
    if op == "argmax":
        if not isinstance(column, str) or not isinstance(ret, str):
            raise QueryRefused("argmax needs column and return")
        xs = _numeric_column(rows, column)
        if not xs:
            raise QueryRefused("argmax over zero rows")
        top = max(xs)
        winners = [r for r, x in zip(rows, xs) if x == top]
        if len(winners) != 1:
            raise QueryRefused(f"argmax tie: {len(winners)} rows at {top}")
        return _emit_string(winners[0].get(ret))
    if op == "topk":
        k = query.get("k")
        if not isinstance(column, str) or not isinstance(ret, str):
            raise QueryRefused("topk needs column and return")
        if not isinstance(k, int) or isinstance(k, bool) or k < 1:
            raise QueryRefused("topk needs k >= 1")
        xs = _numeric_column(rows, column)
        if len(xs) < k:
            raise QueryRefused(f"topk: {len(xs)} rows < k={k}")
        order = sorted(range(len(xs)), key=lambda i: xs[i], reverse=True)
        cut = xs[order[k - 1]]
        if len(xs) > k and xs[order[k]] == cut:
            raise QueryRefused(f"topk tie at the boundary value {cut}")
        return sorted(_emit_string(rows[i].get(ret)) for i in order[:k])
    raise QueryRefused(f"op {op!r} unhandled")


# ---------------------------------------------------------------------------
# Derivation replay (sheet-derivation-v1)
# ---------------------------------------------------------------------------


def _value_universe(
    workbook: dict[str, list[list[object]]],
) -> tuple[set[str], set[Decimal]]:
    strings: set[str] = set()
    numbers: set[Decimal] = set()
    for grid in workbook.values():
        for row in grid:
            for c in row:
                if c is None:
                    continue
                if isinstance(c, Decimal):
                    numbers.add(c)
                    continue
                strings.add(norm_text(c))
                d = _to_decimal(c)
                if d is not None:
                    numbers.add(d)
    return strings, numbers


def _operand_present(v: object, strings: set[str], numbers: set[Decimal]) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        d = _to_decimal(v)
        return d is not None and d in numbers
    if isinstance(v, str):
        if norm_text(v) in strings:
            return True
        d = _to_decimal(v)
        return d is not None and d in numbers
    return False


def replay_derivation(
    workbook: dict[str, list[list[object]]], derivation: dict
) -> object:
    """Replay a sheet-derivation-v1 document. Returns the replayed value, or a
    refusal dict when an operand is absent from the workbook or the document
    is malformed."""
    if (
        not isinstance(derivation, dict)
        or derivation.get("schema") != DERIVATION_SCHEMA
    ):
        return _refusal("refused", reason=f"derivation schema must be {DERIVATION_SCHEMA!r}")
    op = derivation.get("op")
    if op not in _OPS:
        return _refusal("refused", reason=f"op {op!r} not in {_OPS}")
    operands = derivation.get("operands")
    if not isinstance(operands, list):
        return _refusal("refused", reason="operands must be a list")
    places = derivation.get("round", 2)
    if (
        not isinstance(places, int)
        or isinstance(places, bool)
        or places < 0
        or places > 6
    ):
        return _refusal("refused", reason="round must be an int in 0..6")
    strings, numbers = _value_universe(workbook)

    def _check(vals: list[object]) -> list[object]:
        return [v for v in vals if not _operand_present(v, strings, numbers)]

    pairs = op in ("argmax", "topk")
    flat: list[object] = []
    if pairs:
        for p in operands:
            if not (isinstance(p, list) and len(p) == 2):
                return _refusal("refused", reason=f"{op} operands must be [label, value] pairs")
            flat.extend(p)
    else:
        flat = list(operands)
    missing = _check(flat)

    replayed: object
    try:
        if op == "lookup":
            if len(operands) != 1:
                return _refusal("refused", reason="lookup needs exactly one operand")
            v = operands[0]
            d = _to_decimal(v)
            # A producer states operands as JSON values; a numeric-looking
            # STRING ("26.71") is the number 26.71 here exactly as it is for
            # sum/mean/median and for the existence check. Measured 2026-09-02:
            # two models wrote every numeric operand as a string and every
            # correct lookup mismatched on type, not on value.
            replayed = (
                _emit_number(d, places)
                if d is not None
                else _emit_string(v)
            )
        elif op == "list":
            replayed = sorted({_emit_string(v) for v in operands})
        elif op == "count":
            replayed = len(operands)
        elif op in ("sum", "mean", "median"):
            xs = [_to_decimal(v) for v in operands]
            if any(x is None for x in xs) or not xs:
                return _refusal("refused", reason=f"{op} needs >=1 numeric operands")
            ds = [x for x in xs if x is not None]
            if op == "sum":
                replayed = _emit_number(sum(ds, Decimal(0)), places)
            elif op == "mean":
                replayed = _emit_number(sum(ds, Decimal(0)) / len(ds), places)
            else:
                replayed = _emit_number(_median(ds), places)
        elif op == "argmax":
            vals = [_to_decimal(p[1]) for p in operands]
            if any(v is None for v in vals) or not vals:
                return _refusal("refused", reason="argmax needs numeric pair values")
            top = max(v for v in vals if v is not None)
            winners = [p[0] for p, v in zip(operands, vals) if v == top]
            if len(winners) != 1:
                return _refusal("refused", reason=f"argmax tie among {len(winners)} operands")
            replayed = _emit_string(winners[0])
        else:  # topk
            k = derivation.get("k")
            vals = [_to_decimal(p[1]) for p in operands]
            if not isinstance(k, int) or isinstance(k, bool) or k < 1:
                return _refusal("refused", reason="topk needs k >= 1")
            if any(v is None for v in vals) or len(vals) < k:
                return _refusal("refused", reason="topk needs >= k numeric pair values")
            order = sorted(range(len(vals)), key=lambda i: vals[i], reverse=True)  # type: ignore[arg-type]
            replayed = sorted(_emit_string(operands[i][0]) for i in order[:k])
    except (InvalidOperation, ZeroDivisionError, TypeError, OverflowError) as exc:
        return _refusal("refused", reason=f"replay arithmetic failed: {exc}")

    if missing:
        return _refusal("operand_not_in_sheet", missing=missing[:20], replayed=replayed)
    return replayed


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def _load_json_input(path: Path, rel: str, check_name: str) -> dict:
    # `path` is joined LITERALLY at each call site (bundle_dir / "inputs" /
    # "query.json"): the path-join ratchet refuses a non-literal join in the
    # substrate, because a hostile string reaching Path.resolve() unguarded
    # escapes as VERIFIER_INTERNAL_ERROR, which outranks every REJECT.
    if not path.is_file():
        raise FileNotFoundError(f"{rel} not found in bundle at {path.parent.parent}")
    raw = path.read_bytes()
    breach = admit_bytes(raw, check_name=check_name)
    if breach is not None:
        raise InputInadmissible(breach)
    doc = strict_json_loads(raw)
    if not isinstance(doc, dict):
        raise ValueError(f"{rel} must be a JSON object")
    return doc


def _load_workbook(bundle_dir: Path) -> dict[str, list[list[object]]]:
    path = bundle_dir / "data" / "workbook.xlsx"
    if not path.is_file():
        raise FileNotFoundError(f"{WORKBOOK_REL} not found in bundle at {bundle_dir}")
    return read_workbook(path)


class SheetQueryRecompute:
    """Arm A: recompute the answer to the AUDITOR's pinned query."""

    primitive_id: str = "sheet_query_recompute"
    primitive_shape: str = "closed-world query over an .xlsx workbook (lookup / list / count / sum / mean / median / argmax / topk)"
    primitive_version: str = "1"
    primitive_tier: str = "A"
    primitive_contract: str = (
        "answer = evaluate(inputs/query.json [sheet-query-v1], parse(data/workbook.xlsx)) — "
        "the workbook is parsed by the verifier from bytes (stdlib zip+xml; shared, inline "
        "and formula-cached strings; numeric cells as Decimal); the query's layout locates "
        "the header row by header_match, maps logical columns to header texts (casefold, "
        "whitespace-collapsed), assigns each data row a group from a Fund column, a divider "
        "row matching a regex, or the sheet name, and skips rows whose first cell matches "
        "exclude_first_cell; filters are eq/ne (numeric if both sides parse, else "
        "normalized text) and gt/gte/lt/lte (numeric); lookup requires exactly one row; "
        "sum/mean/median are exact Decimal arithmetic rounded HALF_UP to `round` places "
        "(default 2) and emitted as float; count is int; string results are casefolded and "
        "whitespace-collapsed; list/topk results are sorted de-duplicated lists; argmax and "
        "topk refuse ties; any refusal is emitted as {kind: refused, reason}."
    )
    primitive_scope_limits: tuple[str, ...] = (
        "The query is auditor-authored and must be pinned through the spec's pinned_inputs "
        "(inputs/query.json); an unpinned query is producer-writable and the recompute then "
        "answers whatever question the producer chose.",
        "The layout (header texts, group encoding, exclusion regex) is the auditor's reading "
        "of the document, supplied as data; a layout that misreads the sheet yields a "
        "determinate refusal or a wrong-but-deterministic answer, never a pass on a "
        "producer's say-so.",
        "Cells are read from cached values; formulas are not evaluated. Dates, styles and "
        "merged-cell geometry are ignored; a merged header contributes only its anchor cell.",
        "The workbook is producer-visible data; unless the spec ALSO pins data/workbook.xlsx "
        "through pinned_inputs, a producer can ship the workbook under which its answer is "
        "right (measured 2026-09-02, exit 0). The pilot's make_spec pins both.",
        "Divider and exclusion regexes match the cell's whitespace-collapsed text, "
        "case-insensitively; a regex that expects raw whitespace or case never matches.",
        "Grid bounds: rows 1..1,048,576, columns A..16,384, and at most 4,000,000 cells "
        "materialised per sheet; a non-finite numeric cell refuses the workbook.",
        "Refusals carry a per-call nonce so no claimed value can equal one.",
        "Both primitives in this file share one source file, so a #sha256 pin on either "
        "pins the other.",
    )

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        bundle_dir: Path = inputs.bundle_dir
        query = _load_json_input(
            bundle_dir / "inputs" / "query.json", QUERY_REL, "sheet_query_admission"
        )
        workbook = _load_workbook(bundle_dir)
        try:
            value = evaluate_query(workbook, query)
        except (QueryRefused, InvalidOperation, TypeError, OverflowError, ZeroDivisionError) as exc:
            # Arithmetic on a hostile cell (a NaN that parsed, an overflowing
            # quantize) is a determinate refusal, not a checker crash.
            return RecomputedValue(
                value=_refusal("refused", reason=f"{type(exc).__name__}: {exc}"),
                detail=f"sheet_query_recompute refused: {exc}",
            )
        return RecomputedValue(
            value=value,
            detail=f"sheet_query_recompute op={query.get('op')!r} -> {value!r}",
        )


class SheetDerivationReplay:
    """Arm B: replay the PRODUCER's stated derivation against the workbook."""

    primitive_id: str = "sheet_derivation_replay"
    primitive_shape: str = "replay of a producer-stated operation over stated operands, with operand-existence check against the workbook"
    primitive_version: str = "1"
    primitive_tier: str = "A"
    primitive_contract: str = (
        "answer = replay(inputs/derivation.json [sheet-derivation-v1], parse(data/workbook.xlsx)) — "
        "the operation (lookup / list / count / sum / mean / median / argmax / topk) is applied to "
        "the operand values the producer states it used (argmax/topk take [label, value] pairs), "
        "with the same rounding, string-normalization and list conventions as "
        "sheet_query_recompute (a numeric-looking operand, string or number, is a number "
        "for lookup and for every arithmetic op); "
        "sheet_query_recompute; every operand must occur somewhere in the workbook (numbers by "
        "exact Decimal equality against every numeric cell, strings by normalized equality "
        "against every text cell), else the value is {kind: operand_not_in_sheet, missing, "
        "replayed} and no claim can match it."
    )
    primitive_scope_limits: tuple[str, ...] = (
        "This is consistency, not correctness: a wrong selection computed correctly (the "
        "other fund's rows summed right) replays to the producer's own number and passes. "
        "Only sheet_query_recompute under an auditor-pinned query catches that.",
        "Operand existence is workbook-wide, not column-scoped; a value that happens to "
        "occur elsewhere in the workbook satisfies the check.",
        "A lookup derivation has one operand and no arithmetic; the only thing this "
        "primitive can refuse for a lookup is a value absent from the workbook.",
        "Operand existence is EXACT Decimal equality against the cell text. A workbook "
        "whose XML carries binary-float noise (74.45999999999999 for 74.46, which openpyxl "
        "writes by default) makes every honest 2-dp operand 'absent'; canonicalise such a "
        "workbook before binding it, or expect operand_not_in_sheet on honest working.",
        "A non-finite operand (NaN, sNaN, Infinity, as number or string) is 'absent'.",
        "Refusals carry a per-call nonce so no claimed value can equal one.",
        "Both primitives in this file share one source file, so a #sha256 pin on either "
        "pins the other.",
    )

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        bundle_dir: Path = inputs.bundle_dir
        derivation = _load_json_input(
            bundle_dir / "inputs" / "derivation.json",
            DERIVATION_REL,
            "sheet_derivation_admission",
        )
        workbook = _load_workbook(bundle_dir)
        value = replay_derivation(workbook, derivation)
        if isinstance(value, dict):
            return RecomputedValue(
                value=value,
                detail=f"sheet_derivation_replay {value.get('kind')}: {value.get('reason') or value.get('missing')!r}",
            )
        return RecomputedValue(
            value=value,
            detail=f"sheet_derivation_replay op={derivation.get('op')!r} -> {value!r}",
        )


register_primitive(SheetQueryRecompute())
register_primitive(SheetDerivationReplay())
