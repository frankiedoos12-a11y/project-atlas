"""Atlas never runs its tray or window as administrator.

Started from an administrator terminal (or by an elevated program), the tray and window restart themselves
with your normal rights, the same as starting them from the Start menu. Two reasons: Windows blocks drag and
drop from Explorer into an elevated window, and the window reads untrusted files (emails, screenshots, scan
results), which should never happen with full control of the PC. The few things that need administrator
rights (the deep check, Defender's full and offline scans, Defender's extra protection) ask Windows themselves.

How: the new process gets a copy of File Explorer's rights (the shell's token), Microsoft's recommended way to
start a program un-elevated from an elevated one. If Explorer itself runs elevated (UAC turned off), or anything
fails, Atlas simply keeps running as it is.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger(__name__)

TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_ASSIGN_PRIMARY = 0x0008, 0x0002, 0x0001
TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID = 0x0080, 0x0100
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_ELEVATION = 20


def _api():
    """kernel32, advapi32 and user32 with handle-sized arguments (64-bit handles overflow ctypes' default int)."""
    import ctypes
    from ctypes import wintypes

    k32, adv, user32 = ctypes.windll.kernel32, ctypes.windll.advapi32, ctypes.windll.user32
    HANDLE, PHANDLE, DWORD = wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD
    k32.GetCurrentProcess.restype = HANDLE
    k32.OpenProcess.restype = HANDLE
    k32.OpenProcess.argtypes = [DWORD, wintypes.BOOL, DWORD]
    k32.CloseHandle.argtypes = [HANDLE]
    adv.OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
    adv.GetTokenInformation.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD)]
    adv.DuplicateTokenEx.argtypes = [HANDLE, DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, PHANDLE]
    adv.CreateProcessWithTokenW.argtypes = [HANDLE, DWORD, wintypes.LPCWSTR, wintypes.LPWSTR, DWORD,
                                            ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
    user32.GetShellWindow.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(DWORD)]
    return k32, adv, user32


def _elevated_token(token) -> bool:
    import ctypes
    from ctypes import wintypes

    value, size = wintypes.DWORD(), wintypes.DWORD()
    ok = _api()[1].GetTokenInformation(token, TOKEN_ELEVATION, ctypes.byref(value), 4, ctypes.byref(size))
    return bool(ok and value.value)


def is_elevated() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    k32, adv, _ = _api()
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        return _elevated_token(token)
    finally:
        k32.CloseHandle(token)


def run_unelevated(command: list[str]) -> bool:
    """Start the command with File Explorer's (normal) rights. False if that isn't possible."""
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    k32, adv, user32 = _api()

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD)]

    handles = []
    try:
        shell = user32.GetShellWindow()
        pid = wintypes.DWORD()
        if not shell or not user32.GetWindowThreadProcessId(shell, ctypes.byref(pid)) or not pid.value:
            return False  # no desktop shell (e.g. Explorer isn't running)
        process = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
        if not process:
            return False
        handles.append(process)
        shell_token = wintypes.HANDLE()
        if not adv.OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_QUERY, ctypes.byref(shell_token)):
            return False
        handles.append(shell_token)
        if _elevated_token(shell_token):
            return False  # Explorer is elevated too (UAC off): there are no lesser rights to get
        token = wintypes.HANDLE()
        access = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID
        if not adv.DuplicateTokenEx(shell_token, access, None, 2, 1, ctypes.byref(token)):  # impersonation, primary
            return False
        handles.append(token)
        info, started = STARTUPINFO(), PROCESS_INFORMATION()
        info.cb = ctypes.sizeof(STARTUPINFO)
        line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        if not adv.CreateProcessWithTokenW(token, 0, None, line, 0, None, os.getcwd(), ctypes.byref(info),
                                           ctypes.byref(started)):
            log.warning("Couldn't restart without administrator rights (error %s)", k32.GetLastError())
            return False
        k32.CloseHandle(started.hThread)
        k32.CloseHandle(started.hProcess)
        return True
    except OSError:
        log.exception("Couldn't restart without administrator rights")
        return False
    finally:
        for handle in handles:
            k32.CloseHandle(handle)


def restart_unelevated(command: list[str]) -> bool:
    """If this process is elevated, start `command` with normal rights instead. True means: it was restarted,
    so this copy should exit now."""
    if not is_elevated():
        return False
    if run_unelevated(command):
        log.info("Started as administrator: restarted with normal rights instead")
        return True
    log.warning("Running as administrator: couldn't restart with normal rights")
    return False
