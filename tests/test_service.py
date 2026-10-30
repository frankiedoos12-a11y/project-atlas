"""v0.15: the service that starts the tray again, with Windows faked."""

import json
import os
import time

from atlas import service
from atlas.service import GRACE, MAX_STARTS, RETRY, Keeper


class FakeWindows:
    def __init__(self, program):
        self.sessions = [1]
        self.running = {1: False}
        self.quit = set()
        self.command = [str(program), "-m", "atlas.tray"]
        self.started = []
        self.cleared = []

    def active_sessions(self):
        return list(self.sessions)

    def tray_running(self, s):
        return self.running.get(s, False)

    def quit_allowed(self, s):
        return s in self.quit

    def clear_quit(self, s=None):
        self.cleared.append(s)
        self.quit.discard(s)

    def session_user(self, s):
        return f"S-1-5-21-{s}"

    def tray_command(self, sid):
        return self.command

    def start_as_user(self, s, command):
        self.started.append((s, command))
        return True


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def keeper(tmp_path):
    program = tmp_path / "ProjectAtlas.exe"
    program.write_text("")
    clock = Clock()
    return Keeper(FakeWindows(program), clock), clock


def test_waits_after_sign_in_then_starts_the_tray(tmp_path):
    k, clock = keeper(tmp_path)
    assert k.tick() == []  # the Startup shortcut gets its turn first
    clock.now += GRACE
    assert k.tick() == [1]
    assert k.windows.started[0][1] == k.windows.command  # no "--restarted": it simply wasn't started


def test_a_stopped_tray_is_restarted_and_says_so(tmp_path):
    k, clock = keeper(tmp_path)
    k.windows.running[1] = True
    k.tick()
    k.windows.running[1] = False  # ended in Task Manager
    clock.now += GRACE
    assert k.tick() == [1] and k.windows.started[0][1][-1] == "--restarted"


def test_an_approved_quit_lasts_until_sign_out(tmp_path):
    k, clock = keeper(tmp_path)
    k.windows.quit.add(1)
    clock.now += GRACE * 10
    assert k.tick() == []
    k.windows.sessions = []  # signed out
    k.tick()
    assert k.windows.cleared == [1]


def test_retries_are_spaced_and_limited(tmp_path):
    k, clock = keeper(tmp_path)
    k.tick()
    clock.now += GRACE
    assert k.tick() == [1]
    assert k.tick() == []  # too soon
    for _ in range(MAX_STARTS + 3):
        clock.now += RETRY
        k.tick()
    assert len(k.windows.started) == MAX_STARTS  # a tray that keeps crashing isn't started forever


def test_people_who_dont_use_atlas_are_left_alone(tmp_path):
    k, clock = keeper(tmp_path)
    k.windows.command = None
    k.tick()
    clock.now += GRACE
    assert k.tick() == []


def test_not_while_the_installer_replaces_files(tmp_path):
    k, clock = keeper(tmp_path)
    marker = tmp_path / "updating"
    marker.write_text("")
    k.windows.running[1] = True
    k.tick()
    k.windows.running[1] = False
    clock.now += GRACE
    assert k.tick() == []
    old = time.time() - 3600
    os.utime(marker, (old, old))  # left behind: ignored
    assert k.tick() == [1] and k.windows.started[0][1][-1] != "--restarted"


def test_recorded_commands_must_name_a_real_program(tmp_path):
    program = tmp_path / "ProjectAtlas.exe"
    program.write_text("")
    assert service.valid_command(json.dumps([str(program), "-m", "atlas.tray"]))
    assert service.valid_command(json.dumps([str(tmp_path / "gone.exe")])) is None
    assert service.valid_command("not json") is None
    assert service.valid_command(json.dumps({"cmd": "x"})) is None
    assert service.valid_command(None) is None


def test_the_service_program_needs_only_the_standard_library():
    import ast
    import sys
    from pathlib import Path

    tree = ast.parse(Path(service.__file__).read_text(encoding="utf-8"))
    top = {n.names[0].name.split(".")[0] for n in tree.body if isinstance(n, ast.Import)}
    top |= {n.module.split(".")[0] for n in tree.body if isinstance(n, ast.ImportFrom) and n.module}
    assert top <= set(sys.stdlib_module_names) | {"__future__"}
