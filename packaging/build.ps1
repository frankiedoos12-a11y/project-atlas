# Builds dist\ProjectAtlas-Setup.exe from this checkout.
#
# Needs: the dev environment (.venv with Atlas installed), PyInstaller in it
# (pip install pyinstaller), and Inno Setup 6 (winget install JRSoftware.InnoSetup).
# Run from anywhere:  powershell -ExecutionPolicy Bypass -File packaging\build.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$Python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { $Python = "python" }

$version = & $Python -c "import atlas; print(atlas.__version__)"
Write-Host "==> Building Project Atlas $version" -ForegroundColor Cyan

& $Python make_icon.py | Out-Null
$v = ($version.Split(".") + @("0", "0", "0"))[0..3] -join ", "
@"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($v), prodvers=($v)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'PugTheSecurity'),
    StringStruct('FileDescription', 'Project Atlas'),
    StringStruct('FileVersion', '$version'),
    StringStruct('LegalCopyright', 'GPL-3.0-or-later'),
    StringStruct('ProductName', 'Project Atlas'),
    StringStruct('ProductVersion', '$version')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
"@ | Set-Content -Encoding utf8 build\version.txt

& $Python -m PyInstaller --noconfirm --clean --log-level WARN --distpath dist --workpath build\pyinstaller atlas.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
          "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 isn't installed (winget install JRSoftware.InnoSetup)." }
& $iscc /Q "/DAppVersion=$version" ProjectAtlas.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed." }

Write-Host "==> Built $(Join-Path $PSScriptRoot 'dist\ProjectAtlas-Setup.exe')" -ForegroundColor Green
