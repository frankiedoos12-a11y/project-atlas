"""atlas.exe: Atlas's commands, the browser extension helper and the deep check."""

import sys

from atlas.frozen import run

sys.exit(run(sys.argv, "atlas.cli"))
