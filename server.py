"""Compatibility launcher for the canonical :mod:`vulnforge.dashboard` app.

Use ``vulnforge dashboard`` or ``uvicorn vulnforge.dashboard:app`` for new
installations. This module contains no independent routes or data layer.
"""
from vulnforge.dashboard import app, main

if __name__ == "__main__":
    main()
