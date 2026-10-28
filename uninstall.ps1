# Removes Project Atlas from this PC: the program, its Start menu entries, the atlas
# command, start-at-sign-in, the right-click menu entry and the browser extension helper.
#
# Your settings, history and quarantined files are kept (see the message at the end), and
# so is your VirusTotal key. Usually started from Start menu > Uninstall Project Atlas.

param([switch]$Pause)  # -Pause: ask first and wait before closing (for the Start menu shortcut)

$ErrorActionPreference = "Continue"
$InstallDir = if ($env:ATLAS_INSTALL_DIR) { $env:ATLAS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\ProjectAtlas" }
$Venv = Join-Path $InstallDir ".venv"
$Atlas = Join-Path $Venv "Scripts\atlas.exe"

function Say($text) { Write-Host "==> $text" -ForegroundColor Cyan }

function Done {
    if ($Pause) { Read-Host "Press Enter to close" | Out-Null }
    exit
}

# Same as in install.ps1.
function Set-UserPathEntry([string]$dir, [bool]$present) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Environment")
    try {
        $old = [string]$key.GetValue("Path", "", "DoNotExpandEnvironmentNames")
        $parts = @($old -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ne $dir.TrimEnd("\")) })
        if ($present) { $parts += $dir }
        $new = $parts -join ";"
        if ($new -eq $old) { return }
        $key.SetValue("Path", $new, "ExpandString")
    } finally { $key.Close() }
    if (-not ("AtlasEnv" -as [type])) {
        Add-Type -Namespace "" -Name AtlasEnv -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);'
    }
    $r = [UIntPtr]::Zero
    [AtlasEnv]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$r) | Out-Null
}

if (-not (Test-Path $InstallDir)) {
    Write-Host "Project Atlas isn't installed in $InstallDir."
    Done
}

if ($Pause) {
    $answer = Read-Host "Remove Project Atlas from this PC? Your settings, history and quarantine are kept. [y/N]"
    if ($answer -notmatch "^(y|yes)$") { Write-Host "Nothing was changed."; Done }
}

if (Test-Path $Atlas) {
    $data = & $Atlas config 2>$null | Select-String -Pattern "Data folder|Settings" | ForEach-Object { $_.Line.Trim() }
    Say "Turning off start at sign-in, the right-click menu entry and the browser extension helper"
    & $Atlas autostart off | Out-Null
    & $Atlas context-menu off | Out-Null
    & $Atlas browser-extension off | Out-Null
}

Say "Stopping Project Atlas"
Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($Venv, "OrdinalIgnoreCase") } | Stop-Process -Force
Start-Sleep -Seconds 1

Say "Removing the Start menu entries and the atlas command"
Remove-Item (Join-Path ([Environment]::GetFolderPath("Programs")) "Project Atlas") -Recurse -Force -ErrorAction SilentlyContinue
Set-UserPathEntry (Join-Path $InstallDir "bin") $false

Say "Removing $InstallDir"
Set-Location $env:USERPROFILE  # a folder can't be removed while this window is inside it
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $InstallDir) {
    Write-Host "Some files couldn't be removed (still in use?). Restart the PC and delete $InstallDir." -ForegroundColor Yellow
} else {
    Write-Host "Project Atlas has been removed." -ForegroundColor Green
}
Write-Host ""
Write-Host "Kept, in case you reinstall (delete them yourself if you don't want them):"
if ($data) { $data | ForEach-Object { Write-Host "  $_" } }
Write-Host "  Your VirusTotal key: Credential Manager > Windows Credentials > ProjectAtlas"
Done
