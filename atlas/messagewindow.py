"""The window "Scan with Project Atlas" opens for email files (.eml, .msg): the message check, on its own."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from atlas import config, emailcheck
from atlas.app import build_scanner, setup_logging
from atlas.gui import DetailBox, scam_lines, style_window


class MessageWindow:
    def __init__(self, root: tk.Tk, paths: list[Path]):
        self.root = root
        self.scanner, self.store = build_scanner(config.Settings.load())
        self.scale = max(1.0, root.winfo_fpixels("1i") / 96)
        root.title("Project Atlas: is this email a scam?")
        root.geometry(f"{int(820 * self.scale)}x{int(620 * self.scale)}")
        style_window(root, self.scale)
        frame = ttk.Frame(root, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Button(frame, text="Close", command=self.close).pack(side="bottom", anchor="e", pady=(8, 0))
        self.detail = DetailBox(frame)
        self.detail.pack(fill="both", expand=True)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._ui: queue.Queue = queue.Queue()
        self.detail.show([("", f"Checking {len(paths)} email(s)...", None)])
        threading.Thread(target=self._work, args=(paths,), daemon=True).start()
        root.after(150, self._drain)

    def _work(self, paths: list[Path]) -> None:
        lines = []
        for path in paths:
            lines.append(("Email", path.name, None))
            try:
                lines += scam_lines(emailcheck.check_email(path, self.scanner))
            except (OSError, ValueError) as exc:
                lines.append(("", f"Couldn't read it: {exc}", None))
            lines.append(("", "", None))
        self._ui.put(lambda: self.detail.show(lines))

    def _drain(self) -> None:
        while not self._ui.empty():
            self._ui.get_nowait()()
        self.root.after(150, self._drain)

    def close(self) -> None:
        self.store.close()
        self.root.destroy()


def main(paths: list[str]) -> int:
    setup_logging()
    import sys

    if sys.platform == "win32":
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    MessageWindow(root, [Path(p) for p in paths])
    root.mainloop()
    return 0
