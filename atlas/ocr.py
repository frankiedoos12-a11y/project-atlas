"""Read the words in a screenshot with Windows' built-in text recognition (Windows.Media.Ocr).

For the message check: a scam pop-up or a text message is often easier to screenshot (Win+Shift+S) than to
copy. It runs on this PC in the languages Windows is set up for; the picture never leaves the PC.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

IMAGE_TYPES = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff"}
MAX_SIDE = 4000  # Windows' OCR refuses bigger images (OcrEngine.MaxImageDimension is 10000; smaller reads faster)

# PowerShell 5.1 can call WinRT; its async calls are awaited through AsTask.
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
function Await($op, [Type]$type) {
  $task = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); $task.Wait(-1) | Out-Null; $task.Result }
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics, ContentType = WindowsRuntime]
$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($env:ATLAS_OCR_IMAGE)) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($engine -eq $null) { throw 'Windows has no text recognition for your languages' }
$result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
$result.Lines | ForEach-Object { $_.Text }
$stream.Dispose()
"""


class OcrError(Exception):
    pass


def _prepared(image) -> Path:
    """The picture as a PNG Windows can read, no bigger than MAX_SIDE."""
    image = image.convert("RGB")
    if max(image.size) > MAX_SIDE:
        image.thumbnail((MAX_SIDE, MAX_SIDE))
    handle, name = tempfile.mkstemp(suffix=".png", prefix="atlas-ocr-")
    os.close(handle)
    image.save(name)
    return Path(name)


def read_image(image) -> str:
    """The text in a PIL image, one line per line of text."""
    if sys.platform != "win32":
        raise OcrError("Reading screenshots needs Windows")
    path = _prepared(image)
    try:
        out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _SCRIPT],
                             capture_output=True, timeout=60, env={**os.environ, "ATLAS_OCR_IMAGE": str(path)},
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OcrError(f"Windows' text recognition didn't answer: {exc}") from exc
    finally:
        path.unlink(missing_ok=True)
    if out.returncode != 0:
        err = out.stderr.decode("utf-8", "replace").strip().splitlines()
        raise OcrError(err[0] if err else "Windows' text recognition failed")
    return out.stdout.decode("utf-8", "replace").strip()


def read_file(path: Path) -> str:
    from PIL import Image

    with Image.open(path) as image:
        return read_image(image)


def clipboard_image():
    """The picture on the clipboard (a screenshot), or None."""
    from PIL import Image, ImageGrab

    grabbed = ImageGrab.grabclipboard()
    if isinstance(grabbed, Image.Image):
        return grabbed
    if isinstance(grabbed, list):  # copied picture files
        for name in grabbed:
            if Path(name).suffix.lower() in IMAGE_TYPES:
                return Image.open(name)
    return None
