"""serialize.py — workbook -> the text the model sees.

Follows the paper's condition: text-serialised, NO row or column indices, one
line per row, cells tab-separated, blank cells empty, each sheet labelled by
name. Newlines inside a cell (multi-line headers) become " / " so a row stays
one line. Numbers are printed as stored (the workbook's cells are canonical
2-dp values, so this is what a consultant pasting the sheet would see).

Uses openpyxl (the producer/experimenter's view of the document), NOT the
verifier's reader — the serialisation is an input to the model, never a claim.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import openpyxl


def _cell_text(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, float):
        d = Decimal(repr(v))
        s = format(d.normalize(), "f") if d != d.to_integral() else str(int(d))
        return s
    if isinstance(v, Decimal):
        return format(v.normalize(), "f") if v != v.to_integral() else str(int(v))
    return str(v).replace("\r\n", "\n").replace("\n", " / ")


def serialize_workbook(path: Path) -> str:
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    parts: list[str] = []
    for ws in wb.worksheets:
        parts.append(f"### Sheet: {ws.title}")
        for row in ws.iter_rows(values_only=True):
            cells = [_cell_text(c) for c in row]
            while cells and cells[-1] == "":
                cells.pop()
            parts.append("\t".join(cells))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"
