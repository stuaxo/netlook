"""Entry point: `python -m netlook`. Delegates to the DPG frontend, which owns
its own CoreBridge (background thread running the async core) - see ui/dpg.py.
"""
from .ui.dpg import main

if __name__ == "__main__":
    main()
