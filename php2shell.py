#!/usr/bin/env python3
"""PHP2Shell Local Research Framework - entry point.

Thin shim: puts ./src on sys.path so the tool runs from a source checkout.

The script is named ``php2shell.py``, which would otherwise shadow the
``php2shell`` package in ``./src``. The source directory must therefore be
the first import location, even if an editable install added it later in
``sys.path``.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
_PKG = _SRC / "php2shell"

if not _PKG.is_dir():
    sys.exit(
        f"error: expected package directory not found:\n  {_PKG}\n"
        "Create the src/php2shell/ layout, or run from the project root."
    )

if not (_PKG / "__init__.py").is_file():
    sys.exit(f"error: expected package initializer not found:\n  {_PKG / '__init__.py'}")

# An editable install commonly puts src later in sys.path. Merely checking
# membership would leave this script directory first and make Python import
# this file as the `php2shell` module.
_src_path = str(_SRC)
sys.path[:] = [entry for entry in sys.path if entry != _src_path]
sys.path.insert(0, _src_path)

from php2shell.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
