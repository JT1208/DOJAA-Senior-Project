"""CSV export helpers shared by every blueprint that exposes downloads."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Sequence
from typing import Any

from flask import Response


def csv_response(filename: str, header: Sequence[str], rows: Iterable[Sequence[Any]]) -> Response:
    """Return a Flask response with the given rows encoded as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for row in rows:
        writer.writerow(["" if v is None else v for v in row])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
