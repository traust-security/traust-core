from __future__ import annotations

import csv
import io
import re
from itertools import chain

from traust_core.v1.rendering.markdown import Link, Table, inline

# A spreadsheet runs a cell that opens like a formula; report text can come from an audited repo.
_FORMULA = re.compile(r"^(?:[=+@\t\r]|-(?!(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?%?$))")


def csv_table(table: Table) -> str:
    """The table as CSV, one header row; cells on one line, never read as formulas."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for row in chain((table.columns,), table.rows):
        writer.writerow(
            _FORMULA.sub(lambda m: "'" + m.group(0), inline(v.href if isinstance(v, Link) else v))
            for v in row
        )
    return out.getvalue()
