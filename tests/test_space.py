"""Disk space tests. All files live in throwaway folders; the Recycle Bin and OneDrive are faked."""

import os
from pathlib import Path

import pytest

from atlas import space
from atlas.space import GB, MB, DuplicateGroup, FileInfo, apply, blocked_reason, find_duplicates, walk


def make(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def info(path: Path, cloud=False, onedrive=False, size=None, vm=None) -> FileInfo:
    size = size if size is not None else path.stat().st_size
    return FileInfo(path, size, 0.0, 0.0, cloud_only=cloud, in_onedrive=onedrive, used_by_vm=vm)


class FakeCache:
    def __init__(self):
        self.hashes = {}

    def cached_hash(self, path, size, mtime):
        return self.hashes.get((path, size, mtime))

    def cache_hash(self, path, size, mtime, sha):
        self.hashes[(path, size, mtime)] = sha


def test_walk_skips_small_files_app_data_and_links(tmp_path):
    make(tmp_path / "big.iso", b"x" * 2000)
    make(tmp_path / "small.txt", b"x" * 10)
    make(tmp_path / "AppData" / "Local" / "huge.bin", b"x" * 5000)
    make(tmp_path / "project" / "node_modules" / "dep.bin", b"x" * 5000)
    found = {f.path.name for f in walk([tmp_path], min_size=1000)}
    assert found == {"big.iso"}


def test_identical_files_are_grouped_after_full_compare(tmp_path):
    data = os.urandom(3 * MB)
    a = make(tmp_path / "course" / "504.iso", data)
    b = make(tmp_path / "OneDrive" / "504.iso", data)
    c = make(tmp_path / "other.iso", data[:-1] + b"\x00")  # same size, last byte differs
    groups = find_duplicates([info(a), info(b), info(c)], FakeCache())
    assert len(groups) == 1 and groups[0].verified
    assert {f.path for f in groups[0].files} == {a, b}
    assert groups[0].reclaimable == 3 * MB


def test_same_start_and_end_but_different_middle(tmp_path):
    # The quick fingerprint samples three spots; the full hash must still catch differences elsewhere.
    base = bytearray(os.urandom(5 * MB))
    a = make(tmp_path / "a.bin", bytes(base))
    base[3 * MB + 7] ^= 0xFF
    b = make(tmp_path / "b.bin", bytes(base))
    assert find_duplicates([info(a), info(b)], FakeCache()) == []


def test_hashes_are_cached(tmp_path, monkeypatch):
    data = os.urandom(MB)
    files = [info(make(tmp_path / f"{n}.bin", data)) for n in "ab"]
    cache = FakeCache()
    find_duplicates(files, cache)
    monkeypatch.setattr(space, "full_hash", lambda *a, **k: pytest.fail("should use the cache"))
    assert len(find_duplicates(files, cache)) == 1


def test_cloud_only_files_are_never_opened(tmp_path, monkeypatch):
    local = make(tmp_path / "course" / "504.iso", b"x" * 4000)
    cloud = tmp_path / "OneDrive" / "504.iso"  # doesn't exist locally: opening it would fail the test
    opened = []
    real_open = Path.open
    monkeypatch.setattr(Path, "open", lambda self, *a, **k: opened.append(self) or real_open(self, *a, **k))
    groups = find_duplicates([info(local), info(cloud, cloud=True, onedrive=True, size=4000)], FakeCache())
    assert cloud not in opened
    (g,) = groups
    assert not g.verified
    assert g.reclaimable == 4000  # the online copy can be the one kept


def test_reclaimable_keeps_one_local_copy():
    g = DuplicateGroup([FileInfo(Path("a"), 100, 0, 0), FileInfo(Path("b"), 100, 0, 0),
                        FileInfo(Path("c"), 100, 0, 0)], verified=True)
    assert g.reclaimable == 200


def test_vm_disks_are_protected(tmp_path):
    f = info(make(tmp_path / "Windows 10.vdi", b"x"), vm='VirtualBox VM "Windows 10"')
    for action in ("recycle", "move", "free"):
        assert "VirtualBox VM" in blocked_reason(f, action, recycle_limit=10 * GB)


def test_too_big_for_recycle_bin_is_refused():
    f = FileInfo(Path("C:/x/504.iso"), 56 * GB, 0, 0)
    assert "Too big for the Recycle Bin" in blocked_reason(f, "recycle", recycle_limit=47 * GB)
    assert blocked_reason(f, "recycle", recycle_limit=60 * GB) is None
    assert "unknown" in blocked_reason(f, "recycle", recycle_limit=None)
    assert "turned off" in blocked_reason(f, "recycle", recycle_limit=0)
    assert blocked_reason(f, "move") is None  # moving is always possible


def test_free_up_space_only_for_local_onedrive_files():
    assert blocked_reason(FileInfo(Path("a"), 1, 0, 0), "free") == "Not in OneDrive"
    assert blocked_reason(FileInfo(Path("a"), 1, 0, 0, cloud_only=True, in_onedrive=True), "free")
    assert blocked_reason(FileInfo(Path("a"), 1, 0, 0, in_onedrive=True), "free") is None


def test_virtualbox_registry_parsing(tmp_path):
    vm_dir = tmp_path / "VirtualBox VMs" / "Windows 10"
    make(vm_dir / "Windows 10.vbox",
         b'<?xml version="1.0"?><VirtualBox xmlns="http://www.virtualbox.org/"><Machine name="Windows 10">'
         b'<MediaRegistry><HardDisks><HardDisk uuid="{1}" location="Windows 10.vdi" format="VDI"/>'
         b'</HardDisks></MediaRegistry></Machine></VirtualBox>')
    make(tmp_path / ".VirtualBox" / "VirtualBox.xml",
         f'<?xml version="1.0"?><VirtualBox xmlns="http://www.virtualbox.org/"><Global><MachineRegistry>'
         f'<MachineEntry uuid="{{1}}" src="{vm_dir / "Windows 10.vbox"}"/></MachineRegistry></Global>'
         f'</VirtualBox>'.encode())
    disks = space.virtualbox_disks(home=tmp_path)
    assert disks == {str(vm_dir / "Windows 10.vdi").lower(): 'VirtualBox VM "Windows 10"'}


def test_vmware_inventory_parsing(tmp_path):
    vmx = make(tmp_path / "VMs" / "Kali" / "Kali.vmx",
               b'displayName = "Kali Linux"\nscsi0:0.fileName = "Kali-disk1.vmdk"\nnvme0:0.fileName = "D:\\data.vmdk"\n')
    make(tmp_path / "VMware" / "inventory.vmls", f'vmlist1.config = "{vmx}"\n'.encode())
    disks = space.vmware_disks(appdata=tmp_path)
    assert disks[str(vmx.parent / "Kali-disk1.vmdk").lower()] == 'VMware VM "Kali Linux"'
    assert disks["d:\\data.vmdk"] == 'VMware VM "Kali Linux"'


def test_apply_never_removes_every_copy(tmp_path, monkeypatch):
    recycled = []
    monkeypatch.setattr(space, "recycle", lambda f: recycled.append(f.path))
    monkeypatch.setattr(space, "recycle_bin_limit", lambda p: 10 * GB)
    a, b = info(make(tmp_path / "a.iso", b"x")), info(make(tmp_path / "b.iso", b"x"))
    group = DuplicateGroup([a, b], verified=True)
    result = apply("recycle", [a, b], [group])
    assert recycled == [] and result.done == 0
    assert "at least one is always kept" in result.skipped[0]
    result = apply("recycle", [a], [group])
    assert recycled == [a.path] and result.freed == 1


def test_apply_move_to_folder(tmp_path):
    src = info(make(tmp_path / "Downloads" / "big.iso", b"data"))
    dest = tmp_path / "External"
    dest.mkdir()
    make(dest / "big.iso", b"older")  # name clash: must not overwrite
    result = apply("move", [src], folder=dest)
    assert result.done == 1 and not src.path.exists()
    assert (dest / "big (1).iso").read_bytes() == b"data"
    assert (dest / "big.iso").read_bytes() == b"older"


def test_apply_skips_too_big_and_carries_on(tmp_path, monkeypatch):
    recycled = []
    monkeypatch.setattr(space, "recycle", lambda f: recycled.append(f.path))
    monkeypatch.setattr(space, "recycle_bin_limit", lambda p: 1000)
    small = info(make(tmp_path / "small.iso", b"x" * 10))
    huge = info(make(tmp_path / "huge.iso", b"x" * 2000))
    result = apply("recycle", [huge, small])
    assert recycled == [small.path]
    assert "Too big" in result.skipped[0]


def test_hashing_keeps_last_used_date(tmp_path):
    data = os.urandom(MB)
    files = [info(make(tmp_path / f"{n}.bin", data)) for n in "ab"]
    old = 1_600_000_000_000_000_000  # Sept 2020
    for f in files:
        os.utime(f.path, ns=(old, f.path.stat().st_mtime_ns))
    assert len(find_duplicates(files, FakeCache())) == 1
    assert all(f.path.stat().st_atime_ns == old for f in files)
