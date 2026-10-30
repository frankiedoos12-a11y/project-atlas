# PyInstaller recipe for the app: ProjectAtlas.exe (window and tray) and atlas.exe (commands)
# in one folder, sharing one copy of Python and the libraries. Run build.ps1, not this directly.

from PyInstaller.utils.hooks import collect_submodules

hidden = collect_submodules("atlas") + collect_submodules("keyring.backends")
datas = [("../extension", "extension"), ("../atlas/oui.txt.gz", "atlas")]
icon = "build/atlas.ico"


def analysis(script):
    return Analysis([script], pathex=[".."], hiddenimports=hidden, datas=datas, excludes=["pytest"])


app, cli = analysis("app_main.py"), analysis("cli_main.py")

app_exe = EXE(PYZ(app.pure), app.scripts, exclude_binaries=True, name="ProjectAtlas", icon=icon,
              console=False, version="build/version.txt")
cli_exe = EXE(PYZ(cli.pure), cli.scripts, exclude_binaries=True, name="atlas", icon=icon,
              console=True, version="build/version.txt")

COLLECT(app_exe, cli_exe, app.binaries, app.datas, cli.binaries, cli.datas, name="ProjectAtlas")

# The service (ProjectAtlasService.exe) gets its own small folder: `atlas service install` copies it to
# Program Files, where only administrators can change it. It only needs Python's standard library.
service = Analysis(["service_main.py"], pathex=[".."], excludes=["pytest", "tkinter", "PIL", "requests",
                                                                  "watchdog", "keyring", "pystray", "psutil",
                                                                  "ssl", "_ssl", "lzma", "bz2", "_decimal"])
service_exe = EXE(PYZ(service.pure), service.scripts, exclude_binaries=True, name="ProjectAtlasService", icon=icon,
                  console=True, version="build/version.txt")
COLLECT(service_exe, service.binaries, service.datas, name="ProjectAtlasService")
