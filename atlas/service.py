"""The Project Atlas service: keeps the tray running so protection can't be switched off quietly.

A small Windows service (it starts with Windows, runs as the system) that checks every 15 seconds that each
signed-in person who uses Atlas has its tray running. If the tray was quit without an administrator's
approval, crashed, or was ended in Task Manager, the service starts it again, with that person's own normal
rights, never the system's. The tray then says it was restarted.

It does nothing else: the checks themselves stay in the tray, so Atlas never opens a downloaded file or an
email with full control of the PC. Its own program sits in Program Files, which only administrators can
change: a service starting a program that the user (or malware) can replace would hand out full control.

Quitting the tray then needs an administrator's approval (Windows asks). Without it, the tray can be paused
for an hour. Uninstalling Atlas removes the service.

This module only uses Python's standard library, so the service's program stays small.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

SERVICE_NAME = "ProjectAtlas"
DISPLAY_NAME = "Project Atlas Service"
DESCRIPTION = "Keeps Project Atlas protection running: restarts the tray if it's stopped without an " \
              "administrator's approval."
SERVICE_EXE = "ProjectAtlasService.exe"
MACHINE_KEY = r"SOFTWARE\Project Atlas\Service"  # only administrators and the system can change it
USER_KEY = r"Software\Project Atlas"  # each person's tray writes its own command here
MUTEX = "ProjectAtlasGuard"  # held by the tray (app.MUTEX_NAME without "Local\")
POLL = 15  # seconds between looks
GRACE = 45  # after sign-in, give the Startup shortcut time to start the tray first
RETRY = 60  # don't start the tray more often than this in one session
MAX_STARTS = 5  # an hour, per session: a tray that keeps crashing isn't restarted forever
PAUSE_MINUTES = 60


def install_dir() -> Path:
    return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Project Atlas Service"


def _no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


# --- What the tray and the window use ---------------------------------------------------------------------

def installed() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"))
        return True
    except OSError:
        return False


def remember_tray(command: list[str]) -> None:
    """The tray records how to start it, so the service can start it again for this person."""
    if sys.platform != "win32":
        return
    import winreg

    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, USER_KEY) as key:
            winreg.SetValueEx(key, "TrayCommand", 0, winreg.REG_SZ, json.dumps(command))
    except OSError:
        log.warning("Couldn't record the tray's command for the service")


def current_session() -> int:
    import ctypes

    session = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
    return session.value


def cli_command(*args: str) -> list[str]:
    from atlas import frozen

    if frozen.is_frozen():
        return [str(frozen.cli_exe()), *args]
    return [sys.executable, "-m", "atlas", *args]


def run_as_admin(command: list[str]) -> int | None:
    """Run a command with administrator rights (Windows asks). Its exit code, or None if it was refused."""
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE)]

    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW), fMask=0x40 | 0x400,  # NOCLOSEPROCESS, NOUI
                             lpVerb="runas", lpFile=command[0], lpParameters=subprocess.list2cmdline(command[1:]),
                             nShow=0)
    shell32, k32 = ctypes.windll.shell32, ctypes.windll.kernel32
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return None  # cancelled, or no administrator approved
    try:
        k32.WaitForSingleObject(info.hProcess, 120_000)
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return code.value
    finally:
        k32.CloseHandle(info.hProcess)


def ask_to_quit() -> bool:
    """Ask for an administrator's approval to quit the tray in this session. True: approved."""
    return run_as_admin(cli_command("service", "allow-quit", "--session", str(current_session()))) == 0


# --- What the administrator commands do (atlas service install / uninstall / allow-quit) --------------------

def _sc(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sc.exe", *args], capture_output=True, text=True, creationflags=_no_window())


def state() -> str:
    """"running", "stopped", "starting", "stopping" or "not installed"."""
    if not installed():
        return "not installed"
    out = _sc("query", SERVICE_NAME).stdout
    for word in ("RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING"):
        if word in out:
            return {"START_PENDING": "starting", "STOP_PENDING": "stopping"}.get(word, word.lower())
    return "unknown"


def _stop_and_wait(seconds: float = 15) -> None:
    _sc("stop", SERVICE_NAME)
    end = time.monotonic() + seconds
    while time.monotonic() < end and state() not in ("stopped", "not installed"):
        time.sleep(0.5)


def install(dev: bool = False) -> str:
    """Copy the service's program to Program Files and register it to start with Windows. Needs administrator."""
    import shutil

    from atlas import frozen

    if frozen.is_frozen():
        source = frozen.program_dir() / "service"
        if not (source / SERVICE_EXE).exists():
            raise RuntimeError(f"The service's program is missing from {source}. Reinstall Project Atlas.")
        if installed():
            _stop_and_wait()
        shutil.copytree(source, install_dir(), dirs_exist_ok=True)
        binary = f'"{install_dir() / SERVICE_EXE}"'
    elif dev:
        # Development only: this Python can be changed without administrator rights.
        binary = f'"{sys.executable}" -m atlas.service'
    else:
        raise RuntimeError("Install the service from the packaged app (or pass --dev on a development PC).")
    if installed():
        _stop_and_wait()
        result = _sc("config", SERVICE_NAME, "binPath=", binary, "start=", "delayed-auto")
    else:
        result = _sc("create", SERVICE_NAME, "binPath=", binary, "start=", "delayed-auto",
                     "DisplayName=", DISPLAY_NAME)
    if result.returncode != 0:
        raise RuntimeError(f"Windows refused to register the service: {result.stdout.strip() or result.stderr}")
    _sc("description", SERVICE_NAME, DESCRIPTION)
    _sc("failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000")
    _sc("start", SERVICE_NAME)
    return state()


def uninstall() -> None:
    import shutil
    import winreg

    if installed():
        _stop_and_wait()
        _sc("delete", SERVICE_NAME)
    for _ in range(10):  # the program may take a moment to let go of its files
        shutil.rmtree(install_dir(), ignore_errors=True)
        if not install_dir().exists():
            break
        time.sleep(0.5)
    for sub in ("Quit", "Users", ""):
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + (f"\\{sub}" if sub else ""))
        except OSError:
            pass


def allow_quit(session: int) -> None:
    """Let the tray in this session stay closed until that person signs out."""
    import winreg

    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + r"\Quit") as key:
        winreg.SetValueEx(key, str(session), 0, winreg.REG_SZ, time.strftime("%Y-%m-%dT%H:%M:%S"))


# --- The service itself -----------------------------------------------------------------------------------

class Keeper:
    """Decides, every POLL seconds, whose tray to start again. The Windows parts are in `windows`."""

    def __init__(self, windows=None, clock=time.monotonic):
        self.windows = windows or WindowsSessions()
        self.clock = clock
        self.first_seen: dict[int, float] = {}
        self.was_running: dict[int, bool] = {}
        self.starts: dict[int, list[float]] = {}
        self.gave_up: set[int] = set()

    def tick(self) -> list[int]:
        """One look. Returns the sessions whose tray it started."""
        now, started = self.clock(), []
        sessions = self.windows.active_sessions()
        for gone in [s for s in self.first_seen if s not in sessions]:  # signed out
            for table in (self.first_seen, self.was_running, self.starts):
                table.pop(gone, None)
            self.gave_up.discard(gone)
            self.windows.clear_quit(gone)
        for s in sessions:
            first = self.first_seen.setdefault(s, now)
            if self.windows.tray_running(s):
                self.was_running[s] = True
                continue
            if self.windows.quit_allowed(s) or now - first < GRACE:
                continue
            recent = [t for t in self.starts.get(s, []) if now - t < 3600]
            self.starts[s] = recent
            if recent and now - recent[-1] < RETRY:
                continue
            if len(recent) >= MAX_STARTS:
                if s not in self.gave_up:
                    log.warning("The tray in session %s keeps stopping; not starting it again for now", s)
                    self.gave_up.add(s)
                continue
            user = self.windows.session_user(s)
            command = self.windows.tray_command(user) if user else None
            if not command:
                continue  # this person doesn't use Atlas
            if updating(command):  # the installer closed it; it starts it again itself
                self.was_running[s] = False
                continue
            restarted = self.was_running.get(s, False)
            if self.windows.start_as_user(s, command + (["--restarted"] if restarted else [])):
                log.info("Started the tray in session %s (%s)", s, "it had stopped" if restarted else "at sign-in")
                recent.append(now)
                started.append(s)
            self.was_running[s] = False
        return started


class WindowsSessions:
    """Who is signed in, whether their tray runs, and starting it as them (never as the system)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.ct, self.wt = ctypes, wintypes
        H, D = wintypes.HANDLE, wintypes.DWORD
        self.k32, self.adv = ctypes.windll.kernel32, ctypes.windll.advapi32
        self.wts, self.env = ctypes.windll.wtsapi32, ctypes.windll.userenv
        self.k32.OpenMutexW.restype = H
        self.k32.OpenMutexW.argtypes = [D, wintypes.BOOL, wintypes.LPCWSTR]
        self.k32.CloseHandle.argtypes = [H]
        self.k32.LocalFree.argtypes = [ctypes.c_void_p]
        self.wts.WTSEnumerateSessionsW.argtypes = [H, D, D, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(D)]
        self.wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
        self.wts.WTSQueryUserToken.argtypes = [wintypes.ULONG, ctypes.POINTER(H)]
        self.adv.GetTokenInformation.argtypes = [H, ctypes.c_int, ctypes.c_void_p, D, ctypes.POINTER(D)]
        self.adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        self.env.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(ctypes.c_void_p), H, wintypes.BOOL]
        self.env.DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]
        self.adv.CreateProcessAsUserW.argtypes = [H, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                                  ctypes.c_void_p, wintypes.BOOL, D, ctypes.c_void_p,
                                                  wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]

    def active_sessions(self) -> list[int]:
        ct, wt = self.ct, self.wt

        class SESSION(ct.Structure):
            _fields_ = [("id", wt.DWORD), ("name", wt.LPWSTR), ("state", ct.c_int)]

        info, count = ct.c_void_p(), wt.DWORD()
        if not self.wts.WTSEnumerateSessionsW(None, 0, 1, ct.byref(info), ct.byref(count)):
            return []
        try:
            rows = ct.cast(info, ct.POINTER(SESSION))
            return [rows[i].id for i in range(count.value) if rows[i].state == 0 and rows[i].id != 0]  # 0: active
        finally:
            self.wts.WTSFreeMemory(info)

    def tray_running(self, session: int) -> bool:
        handle = self.k32.OpenMutexW(0x00100000, False, f"Session\\{session}\\{MUTEX}")  # SYNCHRONIZE
        if handle:
            self.k32.CloseHandle(handle)
            return True
        return False

    def _user_token(self, session: int):
        token = self.wt.HANDLE()
        return token if self.wts.WTSQueryUserToken(session, self.ct.byref(token)) else None

    def session_user(self, session: int) -> str | None:
        """The signed-in person's SID, e.g. "S-1-5-21-...-1001"."""
        ct, wt = self.ct, self.wt
        token = self._user_token(session)
        if token is None:
            return None
        try:
            buf, size = ct.create_string_buffer(256), wt.DWORD()
            if not self.adv.GetTokenInformation(token, 1, buf, 256, ct.byref(size)):  # TokenUser
                return None
            text = wt.LPWSTR()
            if not self.adv.ConvertSidToStringSidW(ct.c_void_p.from_buffer(buf).value, ct.byref(text)):
                return None
            try:
                return text.value
            finally:
                self.k32.LocalFree(text)
        finally:
            self.k32.CloseHandle(token)

    def tray_command(self, sid: str) -> list[str] | None:
        """What this person's tray recorded; kept in the machine's part of the registry too, so deleting
        it from the person's own settings doesn't switch Atlas off."""
        import winreg

        text = None
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, f"{sid}\\{USER_KEY}") as key:
                text = winreg.QueryValueEx(key, "TrayCommand")[0]
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + r"\Users") as key:
                winreg.SetValueEx(key, sid, 0, winreg.REG_SZ, text)
        except OSError:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + r"\Users") as key:
                    text = winreg.QueryValueEx(key, sid)[0]
            except OSError:
                return None
        return valid_command(text)

    def start_as_user(self, session: int, command: list[str]) -> bool:
        ct, wt = self.ct, self.wt

        class STARTUPINFO(ct.Structure):
            _fields_ = [("cb", wt.DWORD), ("lpReserved", wt.LPWSTR), ("lpDesktop", wt.LPWSTR),
                        ("lpTitle", wt.LPWSTR)] + [(n, wt.DWORD) for n in (
                            "dwX", "dwY", "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars",
                            "dwFillAttribute", "dwFlags")] + [
                        ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD), ("lpReserved2", ct.c_void_p),
                        ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]

        class PROCESS_INFORMATION(ct.Structure):
            _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("pid", wt.DWORD), ("tid", wt.DWORD)]

        token = self._user_token(session)
        if token is None:
            return False  # never fall back to starting it as the system
        env = ct.c_void_p()
        try:
            if not self.env.CreateEnvironmentBlock(ct.byref(env), token, False):
                env = ct.c_void_p()
            info, started = STARTUPINFO(), PROCESS_INFORMATION()
            info.cb, info.lpDesktop = ct.sizeof(STARTUPINFO), "winsta0\\default"
            line = ct.create_unicode_buffer(subprocess.list2cmdline(command))
            ok = self.adv.CreateProcessAsUserW(token, None, line, None, None, False, 0x00000400 | 0x08000000,
                                               env, str(Path(command[0]).parent), ct.byref(info),
                                               ct.byref(started))  # unicode environment, no window
            if not ok:
                log.warning("Couldn't start the tray in session %s (error %s)", session, ct.GetLastError())
                return False
            self.k32.CloseHandle(started.hThread)
            self.k32.CloseHandle(started.hProcess)
            return True
        finally:
            if env:
                self.env.DestroyEnvironmentBlock(env)
            self.k32.CloseHandle(token)

    def quit_allowed(self, session: int) -> bool:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + r"\Quit") as key:
                winreg.QueryValueEx(key, str(session))
            return True
        except OSError:
            return False

    def clear_quit(self, session: int | None = None) -> None:
        """Forget an approved quit when that person signs out (None: everyone's, when Windows starts)."""
        import winreg

        try:
            if session is None:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + r"\Quit")
                return
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MACHINE_KEY + r"\Quit", 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, str(session))
        except OSError:
            pass


def valid_command(text: str | None) -> list[str] | None:
    """A recorded tray command: a list of words whose program exists."""
    try:
        command = json.loads(text or "")
    except ValueError:
        return None
    if (not isinstance(command, list) or not command or not all(isinstance(w, str) for w in command)
            or not Path(command[0]).is_file()):
        return None
    return command


def updating(command: list[str], minutes: int = 10) -> bool:
    """The installer leaves an "updating" file next to the program while it replaces it. An old one is
    ignored, so it can't switch the service off for good."""
    try:
        age = time.time() - (Path(command[0]).parent / "updating").stat().st_mtime
    except OSError:
        return False
    return age < minutes * 60


def _log_to_file() -> None:
    from logging.handlers import RotatingFileHandler

    try:  # next to the program: in Program Files, only administrators can change it
        handlers = [RotatingFileHandler(Path(sys.executable).parent / "service.log", maxBytes=500_000,
                                        backupCount=1, encoding="utf-8")]
    except OSError:
        handlers = [logging.NullHandler()]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


def _serve(stop: threading.Event) -> None:
    keeper = Keeper()
    keeper.windows.clear_quit()  # approvals last until sign-out; after a restart nobody is signed in
    log.info("Project Atlas Service started")
    while not stop.is_set():
        try:
            keeper.tick()
        except Exception:
            log.exception("Look failed")
        stop.wait(POLL)
    log.info("Project Atlas Service stopped")


def main() -> int:
    """The service's program. Run by Windows; `--console` runs the same loop in a window, for testing."""
    import ctypes
    from ctypes import wintypes

    _log_to_file()
    stop = threading.Event()
    if "--console" in sys.argv:
        logging.getLogger().addHandler(logging.StreamHandler())
        try:
            _serve(stop)
        except KeyboardInterrupt:
            pass
        return 0

    class STATUS(ctypes.Structure):
        _fields_ = [(n, wintypes.DWORD) for n in ("type", "state", "accepted", "exit", "specific_exit",
                                                   "checkpoint", "wait_hint")]

    adv = ctypes.windll.advapi32
    HANDLER = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)
    MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.c_void_p)
    adv.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    adv.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, HANDLER, ctypes.c_void_p]
    adv.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(STATUS)]
    status, handle = STATUS(type=0x10), wintypes.HANDLE()  # a service in its own process

    def report(new_state: int) -> None:
        status.state = new_state
        status.accepted = (0x1 | 0x4) if new_state == 4 else 0  # stop and shutdown, once running
        adv.SetServiceStatus(handle, ctypes.byref(status))

    def handler(control, event_type, event_data, context):
        if control in (1, 5):  # stop, shutdown
            report(3)  # stop pending
            stop.set()
        return 0

    def service_main(argc, argv):
        handle.value = adv.RegisterServiceCtrlHandlerExW(SERVICE_NAME, handler_ref, None)
        report(4)  # running
        _serve(stop)
        report(1)  # stopped

    handler_ref, main_ref = HANDLER(handler), MAIN(service_main)

    class ENTRY(ctypes.Structure):
        _fields_ = [("name", wintypes.LPWSTR), ("proc", MAIN)]

    table = (ENTRY * 2)(ENTRY(SERVICE_NAME, main_ref), ENTRY(None, MAIN()))
    if not adv.StartServiceCtrlDispatcherW(table):
        print("This is the Project Atlas Service's program: Windows starts it. Use `atlas service` instead.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
