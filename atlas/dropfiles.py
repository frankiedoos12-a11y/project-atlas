"""Let files be dropped onto a Tk widget from Explorer (Tk can't do it by itself).

Uses tkdnd through tkinterdnd2, loaded into the window that's already open. Without it, dropping simply
isn't offered; the Open button still works.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

log = logging.getLogger(__name__)


def accept_files(widget, on_drop: Callable[[list[str]], None]) -> bool:
    """Call on_drop(paths) when files are dropped on the widget. False if dropping isn't available."""
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD

        TkinterDnD._require(widget.winfo_toplevel())
        widget.drop_target_register(DND_FILES)
    except Exception:  # missing package or Tcl extension: no dropping, nothing else breaks
        log.warning("Drag and drop isn't available", exc_info=True)
        return False

    def dropped(event):
        paths = [p for p in widget.tk.splitlist(event.data) if p]
        if paths:
            on_drop(paths)
        return event.action

    widget.dnd_bind("<<Drop>>", dropped)
    return True
