# Project Atlas installer and updater for Windows 10/11.
#
# In PowerShell (no administrator rights needed):
#     irm https://raw.githubusercontent.com/frankiedoos12-a11y/project-atlas/main/install.ps1 | iex
#
# Run the same line again any time to update. Your settings, history, quarantine and
# VirusTotal key are kept: they live outside the program folder.
#
# What it does:
#   1. Finds Python 3.12+ (python.org build), or installs Python 3.13 for your user with winget.
#      The Microsoft Store build of Python is avoided: Windows hides its AppData files from other programs.
#   2. Downloads Atlas into %LOCALAPPDATA%\Programs\ProjectAtlas and installs it in its own environment.
#   3. Asks for your VirusTotal API key once (stored in Windows Credential Manager).
#   4. Starts Atlas in the tray at sign-in, adds "Scan with Project Atlas" to the right-click
#      menu, connects the browser extension helper, and starts the tray now.

& {
    # Not "Stop": in Windows PowerShell that turns anything a program writes to stderr (py's
    # "no such version", pip warnings) into a fatal error. Programs are judged by their exit
    # codes instead, and file steps pass -ErrorAction Stop themselves.
    $ErrorActionPreference = "Continue"
    $ProgressPreference = "SilentlyContinue"  # makes downloads much faster in Windows PowerShell

    $Repo = if ($env:ATLAS_REPO) { $env:ATLAS_REPO } else { "frankiedoos12-a11y/project-atlas" }
    $Branch = if ($env:ATLAS_BRANCH) { $env:ATLAS_BRANCH } else { "main" }
    $InstallDir = if ($env:ATLAS_INSTALL_DIR) { $env:ATLAS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\ProjectAtlas" }
    $SetUp = -not $env:ATLAS_NO_SETUP  # for testing the download and install steps only
    $Venv = Join-Path $InstallDir ".venv"

    function Say($text) { Write-Host "==> $text" -ForegroundColor Cyan }

    function Find-Python {
        $found = @()
        if (Get-Command py.exe -ErrorAction SilentlyContinue) {
            foreach ($v in "3.13", "3.12", "3.14") {
                $exe = & py.exe "-$v" -c "import sys; print(sys.executable)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $exe) { $found += $exe.Trim() }
            }
        }
        foreach ($v in "313", "312", "314") {
            $found += Join-Path $env:LOCALAPPDATA "Programs\Python\Python$v\python.exe"
            $found += Join-Path $env:ProgramFiles "Python$v\python.exe"
        }
        foreach ($exe in $found) {
            if ((Test-Path $exe) -and ($exe -notmatch "WindowsApps")) { return $exe }
        }
        return $null
    }

    # Adds or removes a folder in the user's PATH. Read and written without expanding
    # %VARIABLES%, so entries like %USERPROFILE%\bin keep working.
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
        # Tell Windows, so terminals opened from now on see the change without signing out.
        if (-not ("AtlasEnv" -as [type])) {
            Add-Type -Namespace "" -Name AtlasEnv -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);'
        }
        $r = [UIntPtr]::Zero
        [AtlasEnv]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$r) | Out-Null
    }

    function New-Shortcut([string]$path, [string]$target, [string]$arguments, [string]$description, [string]$icon) {
        $link = (New-Object -ComObject WScript.Shell).CreateShortcut($path)
        $link.TargetPath = $target
        $link.Arguments = $arguments
        $link.WorkingDirectory = $InstallDir
        $link.Description = $description
        if ($icon -and (Test-Path $icon)) { $link.IconLocation = $icon }
        $link.Save()
    }

    if ([Environment]::OSVersion.Platform -ne "Win32NT") { throw "Project Atlas runs on Windows only." }

    Say "Looking for Python 3.12 or newer"
    $Python = Find-Python
    if (-not $Python) {
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            throw "Python 3.12+ is needed. Install it from https://www.python.org/downloads/ and run this again."
        }
        Say "Installing Python 3.13 for your user (winget)"
        winget install --exact --id Python.Python.3.13 --scope user --silent --accept-package-agreements --accept-source-agreements | Out-Host
        $Python = Find-Python
        if (-not $Python) { throw "Python was installed but couldn't be found. Open a new PowerShell window and run this again." }
    }
    Say "Using $Python"

    # An update replaces files the running tray and helpers hold open.
    $running = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($Venv, "OrdinalIgnoreCase") }
    if ($running) {
        Say "Stopping the running Project Atlas so it can be updated"
        $running | Stop-Process -Force
        Start-Sleep -Seconds 1
    }

    Say "Downloading Project Atlas ($Repo, $Branch)"
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("atlas-install-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp -ErrorAction Stop | Out-Null
    try {
        $zip = Join-Path $tmp "atlas.zip"
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/$Repo/archive/refs/heads/$Branch.zip" -OutFile $zip -ErrorAction Stop
        Unblock-File $zip -ErrorAction Stop
        Expand-Archive -Path $zip -DestinationPath $tmp -Force -ErrorAction Stop
        $src = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
        New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction Stop | Out-Null
        foreach ($old in "atlas", "extension", "tests") {
            $p = Join-Path $InstallDir $old
            if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction Stop }
        }
        Copy-Item -Path (Join-Path $src.FullName "*") -Destination $InstallDir -Recurse -Force -ErrorAction Stop
    } finally {
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) {
        Say "Creating Atlas's own Python environment"
        & $Python -m venv $Venv
        if ($LASTEXITCODE -ne 0) { throw "Couldn't create the Python environment." }
    }
    $VenvPython = Join-Path $Venv "Scripts\python.exe"
    $Atlas = Join-Path $Venv "Scripts\atlas.exe"

    Say "Installing Atlas and its libraries (about a minute the first time)"
    & $VenvPython -m pip install --quiet --disable-pip-version-check --upgrade pip 2>$null
    & $VenvPython -m pip install --quiet --disable-pip-version-check --editable $InstallDir
    if ($LASTEXITCODE -ne 0) { throw "Installing Atlas's libraries failed (see the messages above)." }

    if (-not $SetUp) {
        Write-Host "Installed to $InstallDir (setup steps skipped)." -ForegroundColor Green
        return
    }

    & $VenvPython -c "from atlas import config; import sys; sys.exit(0 if config.get_api_key() else 1)"
    if ($LASTEXITCODE -ne 0) {
        Say "Atlas needs your VirusTotal API key (it's stored in Windows Credential Manager, never in a file)"
        & $Atlas set-key
    }

    Say "Setting up: start at sign-in, right-click scanning, browser extension helper"
    & $Atlas autostart on | Out-Null
    & $Atlas context-menu on | Out-Null
    & $Atlas browser-extension on | Out-Null

    Say "Adding Project Atlas to the Start menu, and the atlas command to terminals"
    $Bin = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Path $Bin -Force -ErrorAction Stop | Out-Null
    # A one-line forwarder: only "atlas" goes on PATH, not the environment's own python.exe and pip.
    Set-Content -Path (Join-Path $Bin "atlas.cmd") -Value "@`"%~dp0..\.venv\Scripts\atlas.exe`" %*" -Encoding ASCII -ErrorAction Stop
    Set-UserPathEntry $Bin $true
    if (($env:PATH -split ";") -notcontains $Bin) { $env:PATH = "$env:PATH;$Bin" }  # this window too
    $icon = & $VenvPython -c "from atlas.contextmenu import icon_path; print(icon_path())"
    $menu = Join-Path ([Environment]::GetFolderPath("Programs")) "Project Atlas"
    New-Item -ItemType Directory -Path $menu -Force -ErrorAction Stop | Out-Null
    New-Shortcut (Join-Path $menu "Project Atlas.lnk") (Join-Path $Venv "Scripts\atlas-gui.exe") "" "Open the Project Atlas window" $icon
    New-Shortcut (Join-Path $menu "Project Atlas protection (tray).lnk") (Join-Path $Venv "Scripts\atlas-tray.exe") "" "Start Project Atlas protection in the tray" $icon
    New-Shortcut (Join-Path $menu "Uninstall Project Atlas.lnk") (Join-Path $PSHOME "powershell.exe") "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'uninstall.ps1')`" -Pause" "Remove Project Atlas from this PC" $icon

    Say "Starting Project Atlas in the tray"
    Start-Process (Join-Path $Venv "Scripts\atlas-tray.exe")

    $version = & $VenvPython -c "import atlas; print(atlas.__version__)"
    Write-Host ""
    Write-Host "Project Atlas $version is installed and running (look for the blue globe by the clock;" -ForegroundColor Green
    Write-Host "if it isn't there, click the ^ arrow next to the clock)." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Open the window:  Start menu > Project Atlas, or click the globe"
    Write-Host "  Commands:         type  atlas --help  in any PowerShell or Command Prompt window"
    Write-Host "  Update:           run the same install line again"
    Write-Host "  Uninstall:        Start menu > Uninstall Project Atlas"
    Write-Host "  Program folder:   $InstallDir"
    Write-Host ""
    Write-Host "Optional, once per browser: add the link-checker extension."
    Write-Host "  Open chrome://extensions (or edge://extensions), turn on Developer mode,"
    Write-Host "  click Load unpacked and choose: $(Join-Path $InstallDir 'extension')"
    if (-not (Test-Path (Join-Path $env:ProgramFiles "7-Zip\7z.exe"))) {
        Write-Host ""
        Write-Host "Tip: install 7-Zip (winget install 7zip.7zip) so Atlas can look inside every kind of disc image."
    }
}
