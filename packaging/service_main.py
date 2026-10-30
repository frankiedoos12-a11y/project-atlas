"""ProjectAtlasService.exe: the Windows service that keeps the tray running (see atlas/service.py)."""

import sys

from atlas.service import main

sys.exit(main())
