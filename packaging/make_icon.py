"""Draw Atlas's globe into build/atlas.ico for the programs and the setup."""

from pathlib import Path

from atlas.tray import make_icon

out = Path(__file__).parent / "build" / "atlas.ico"
out.parent.mkdir(exist_ok=True)
make_icon("ok").save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print(out)
