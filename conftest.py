"""Ensure src/ is importable when running pytest from a source checkout."""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir():
    # An editable install may have added src after the project root, where the
    # top-level php2shell.py launcher would shadow the package during pytest
    # collection. Ensure src wins regardless of an existing later entry.
    _src_path = str(_SRC)
    sys.path[:] = [entry for entry in sys.path if entry != _src_path]
    sys.path.insert(0, _src_path)
