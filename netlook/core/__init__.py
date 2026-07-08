"""Core: data models, actions, and the async network engine. No UI toolkit dependency
and no UI-shape concepts (a "row", "tabs", ...) either - see ui/base.py for those.
ui/dpg.py and ui/textual.py are the two frontends currently built on top of this.

Importing this package registers every built-in Service subclass (see .services)
against the shared registry in .models, so callers get the full set of supported
protocols without having to import .services themselves just for its side effects.
"""
from . import services  # noqa: F401 - registers Service subclasses via @register
