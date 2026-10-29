"""ProjectAtlas.exe: the window (default) and the tray (`-m atlas.tray`), with no console."""

import sys

from atlas.frozen import run

sys.exit(run(sys.argv, "atlas.gui"))
