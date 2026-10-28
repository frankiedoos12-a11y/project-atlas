# Project Atlas

VirusTotal-powered protection for Windows 11. It runs **alongside** Windows Defender, not instead of it. No ads, no upsells, and all data stays on your PC.

## Install

On any Windows 10 or 11 PC, open **PowerShell** (Start menu, type *PowerShell*, press Enter; no administrator rights needed) and paste:

```powershell
irm https://raw.githubusercontent.com/frankiedoos12-a11y/project-atlas/main/install.ps1 | iex
```

It installs Python 3.13 for your user if needed, downloads Atlas to `%LOCALAPPDATA%\Programs\ProjectAtlas`, and asks for your VirusTotal API key once (each PC keeps its key in its own Windows Credential Manager). Then it sets everything up and starts Atlas. You can [read the installer](install.ps1) first; it's short.

- **Update:** run the same line again. Settings, history and your key are kept.
- **Uninstall:** Start menu > **Uninstall Project Atlas**. Your settings, history, quarantine and key are kept in case you reinstall; it tells you where they are.

## Starting and using Atlas

After installing you don't need to start anything: **Atlas is already running**, and it starts by itself every time you sign in. You'll find:

| What | Where | What it's for |
|---|---|---|
| **The tray globe** | Next to the clock (if it's hidden, click the **^** arrow there) | Protection is running while it's there. Click it to open the window; right-click for quick actions. |
| **Project Atlas** | Start menu | Opens the Atlas window: startup items, cleanup, disk space, browsers, quarantine. |
| **Project Atlas protection (tray)** | Start menu | Starts protection again if you chose *Quit* in the tray. |
| **Scan with Project Atlas** | Right-click any file or folder in Explorer (Windows 11: *Show more options*) | Checks it with VirusTotal right now. |
| **`atlas` commands** | Type them in any **PowerShell** or **Command Prompt** window | The same features as text, e.g. `atlas scan C:\Users\me\Downloads\setup.exe`. See [Commands](#commands). |

`atlas` works in any folder, but only in windows opened **after** installing: if a window was already open, close it and open a new one. To check, type `atlas --version`.

What Atlas does:

## 1. Download guard

Every new file in your **Downloads** and **Desktop** folders gets:

1. **Hashed** (SHA-256) and looked up on VirusTotal. Only the hash is sent, never the file.
2. **Traced** to where it came from. Windows tags downloads with a "Mark of the Web" that records the download link and the page it was on, and Atlas checks both sites on VirusTotal too. Only the site name is sent for the page, never its full address.
3. **Signature-checked**. Windows verifies who signed it and whether it has been tampered with since.
4. **Judged**:

| Verdict | Meaning | What happens |
|---|---|---|
| Clean | No engines flagged it | Nothing (logged) |
| Unknown | VirusTotal has no results for it, it can run code, and it isn't validly signed | Warning pop-up |
| Suspicious | A few engines flagged it, its signature is broken, or a site involved has a bad reputation | Warning pop-up |
| Malicious | At least 3 engines flagged the file or its download link | Moved to quarantine + pop-up |

**ZIP, 7z, RAR and ISO files are checked inside too**, without extracting anything to disk. Malware is often sent in an archive: the archive is brand new to VirusTotal, but the program inside is well known. Atlas hashes every program inside (including ZIPs inside ZIPs, up to 25 per archive) and looks those up. It also warns about programs disguised as documents (`Invoice.pdf.exe`) and password-protected archives holding programs, a common way to sneak past scanners. A new archive whose contents are all known and clean counts as clean. Zip bombs are detected and never expanded. 7z, RAR and ISO are read with [7-Zip](https://www.7-zip.org/) when it's installed, otherwise with Windows' built-in `tar`. `tar` can't read most modern disc images (UDF), so if it sees nothing inside, Atlas says so instead of calling the disc empty. Only plain `.zip` files are opened as ZIPs: installers, `.jar` and `.msix` files are ZIPs underneath but run code themselves, so their contents never vouch for them.

### Scan any file from the right-click menu

Turn it on once with the tray's **"Scan with Project Atlas" in right-click menu** tick box (or `atlas context-menu on`). Then right-click any file or folder, choose **Show more options**, then **Scan with Project Atlas**. (Windows 11 only lets Store apps into the short top menu; holding Shift while right-clicking skips straight to the full one.)

A results window runs the same checks as the download guard. Folders are checked file by file, up to 1,000. Selecting several items gathers them all into one window. Nothing is quarantined automatically, because you asked to look, so you decide:

- **View on VirusTotal**, **Open file location**
- **Check again** asks VirusTotal afresh instead of using the 24-hour cache
- **Upload to VirusTotal...** for files VirusTotal has never seen (asks first: uploaded files are shared with VirusTotal Intelligence subscribers)
- **Move to quarantine...** (restore it later from the Quarantine tab)

The entry is registered for your user only, needs no administrator rights, and `atlas context-menu off` removes it completely.

## 2. Startup-item monitor

Malware and adware almost always set themselves to start automatically, so they come back after every reboot. Atlas checks every place they can do that:

- Registry **Run / RunOnce** keys (yours and machine-wide)
- **Startup folders**
- **Scheduled tasks**
- **Services and drivers**
- **Hijacks**: a replaced Windows shell or Userinit, and "debugger" hijacks where opening one program secretly starts another

Each item's file is signature-checked, and anything not made by Microsoft is looked up on VirusTotal. Atlas also flags tricks malware uses, like hidden encoded PowerShell commands, `mshta`, and unsigned programs starting from Temp folders.

Every 10 minutes Atlas compares against what it saw before. When something **new** sets itself to start automatically, you get a pop-up saying what it is, who signed it, and where it lives.

**Switch off / Switch on** in the window turns an item off the same way Task Manager's *Startup apps* page does, so the two always agree and it's undone with one click. It works for Run keys, startup-folder shortcuts and scheduled tasks. Machine-wide items and most tasks need Atlas run as administrator; Microsoft items ask before switching off. Services and drivers are left to Windows' own Services tool, because switching the wrong one off can stop Windows starting.

## 3. Cleanup

Scanning only looks. Nothing is removed until you choose **Clean selected** and confirm.

| Category | Pre-selected | What happens |
|---|---|---|
| Temporary files | Yes | Deleted. Skips anything changed in the last day, and anything a startup item runs from Temp |
| Browser caches (Chrome, Edge, Brave, Opera, Firefox) | Yes | Emptied. Locked while that browser is open. You stay signed in |
| Crash dumps and error reports | Yes | Deleted |
| Graphics shader caches (DirectX, NVIDIA, AMD, Intel) | Yes | Emptied. Games rebuild them, so the first launch afterwards may stutter briefly. Files a running game holds open are skipped |
| Leftover startup entries (program deleted) | Yes | Your own registry entries are backed up to a `.reg` file in `%LOCALAPPDATA%\ProjectAtlas\backups`, then removed. Startup-folder shortcuts go to the Recycle Bin. Machine-wide entries, services and tasks are listed but need administrator rights |
| Old installers in Downloads (30+ days) | No | Recycle Bin |
| App data with no installed program (unused 180+ days) | No | Recycle Bin. Atlas can't be certain, so review each one |
| Recycle Bin | No | Emptied for good. This can't be undone, so it's never ticked for you |

Deletion only ever happens inside the folder an item was found in. Every removal is logged, and one failure (e.g. a file in use) never stops the rest. `atlas cleanup` prints the same report in the console.

## 4. Disk space: duplicates and big files

The **Disk space** tab finds copies of the same file and big files that take up room, starting from your user folder (`space_scan_folders` in the settings).

- **Duplicates** are found by size, then a quick sample of each file, then a full SHA-256 compare. Hashes are remembered, so the next scan is fast. Only files over `duplicate_min_mb` (10 MB) are compared.
- **Big files** lists everything over `big_file_min_mb` (500 MB), with its type, where it lives and when it was last used.
- **OneDrive aware:** files that are only online are never opened or downloaded. If an online-only file has the same name and size as a local one, it is shown as a likely copy marked "not compared". *Free up space* turns a local OneDrive file into online-only, the same as OneDrive's own menu.
- **Safe actions:** *Recycle* (you can restore from the Recycle Bin), *Move to folder…* (e.g. an external drive) or *Free up space*. At least one copy of every duplicate is always kept. A file too big for your Recycle Bin is refused rather than silently deleted forever, and virtual machine disks used by VirtualBox or VMware are protected.

`atlas space` prints the same report in the console without changing anything.

## 5. Browsers: ad spam and link checking

The **Browsers** tab covers Chrome, Edge, Brave, Opera and Firefox, every profile.

- **Check a link before you open it.** Paste a link from an email, text or ad. Atlas never visits it. It asks VirusTotal about the exact link and its site, and spots scam tricks offline: a familiar name inside someone else's address (`paypal.com.account-verify.xyz`), look-alike foreign letters, an `@` hiding the real destination, bare IP addresses and link shorteners. A single "suspicious" vote on a normal site is treated as noise. The tray's **Check link on clipboard** does the same from anywhere: copy a link, then click it.
- **Sites allowed to send notifications.** "Click Allow to prove you're not a robot" pages use this to push fake virus alerts and ads. Each site is checked on VirusTotal. **Block notifications** switches a site to *Block* (the browser must be closed; its settings file is backed up first to `%LOCALAPPDATA%\ProjectAtlas\backups`).
- **Extensions.** Flags the signs of adware: installed by another program from outside the store, forced on by a policy, loaded unpacked, or taking over your search engine, home page or new tab page. Store extensions bundled by a program you installed (Adobe Acrobat, Google Docs Offline) are noted, not flagged. **Open in browser to remove** jumps to that extension in the browser's own extensions page.

`atlas browsers` and `atlas check-url LINK` do the same from the console.

### Browser extension: check links as you open them

The **Project Atlas Link Checker** extension (Chrome, Edge, Brave) asks Atlas on your PC about every page before you use it. A dangerous or suspicious page is replaced by a warning, with *Go back to safety* or *Continue anyway* (remembered until the browser restarts). The toolbar globe shows the current page's verdict, and right-clicking any link gives **Check link with Project Atlas**.

- **Your key never enters the browser.** The extension talks to a small Atlas helper on your PC (Chrome's *native messaging*), which uses the key from Credential Manager.
- **Privacy:** pages you open are checked without their `?query` and `#fragment`, which often hold search terms or login tokens. Only links you right-click are checked in full. Addresses on your PC or home network (`192.168.x.x`, `localhost`, `router`, `*.local`) are never sent anywhere.
- Unknown sites aren't blocked, only marked `?` on the globe, so new and small sites still open normally.

**Set up:** the installer connects the helper (`atlas browser-extension on`). Then, once per browser: open `chrome://extensions` (or `edge://extensions`), turn on **Developer mode**, click **Load unpacked**, paste `%LOCALAPPDATA%\Programs\ProjectAtlas\extension` into the folder box's address bar, press Enter and click **Select Folder**. Atlas's own ad-spam finder recognizes it, so it isn't flagged for being loaded unpacked.

## The Atlas window

Open it from **Start menu > Project Atlas**, by clicking the tray globe, or with `atlas gui`. It has six tabs:

- **Startup items**: everything set to start automatically, colour-coded by verdict, with a filter (*Not Microsoft*, *Needs a look*, *Microsoft*, *Leftovers*, *Everything*), a search box, sortable columns, and a details panel showing publisher, file, registry location and why Atlas judged it that way. Buttons open the file's folder or its VirusTotal page, and **Switch off / Switch on** the item. **Check now** re-runs a full check.
- **Activity**: every file Atlas has checked, newest first, with where it was downloaded from.
- **Cleanup**: finds junk and leftovers with no home (see below). Tick what to remove, then **Clean selected**.
- **Disk space**: duplicate files and big files, with *Recycle*, *Move to folder…* and *Free up space* (see above).
- **Browsers**: link checker, notification spam and extensions (see above).
- **Quarantine**: files Atlas moved out of the way, with **Restore** (asks first).

The header shows whether protection is running and whether your VirusTotal key is connected.

## The tray icon

The globe is **blue** while protecting, **grey** while paused, and **red** after an alert (until you choose *Clear alert*). Left-click it to open the Atlas window, or right-click it for:

- Open Project Atlas
- Pause protection
- Check startup items now
- Scan watched folders now
- Check link on clipboard
- Open activity log / quarantine folder / settings file
- Start with Windows
- "Scan with Project Atlas" in right-click menu
- Quit

## Commands

Type these in any PowerShell or Command Prompt window, from any folder (open a new window after installing). `atlas --help` lists them, and `atlas COMMAND --help` explains one.

| Command | What it does |
|---|---|
| `atlas tray` | Run in the system tray (same as `atlas-tray.exe`) |
| `atlas gui` | Open the Atlas window (same as `atlas-gui.exe`) |
| `atlas guard` | Same protection, in a console window (Ctrl+C to stop) |
| `atlas autoruns` | Check everything set to start automatically (`--all` to include Microsoft items) |
| `atlas cleanup` | Report junk that can be removed (read-only; clean from the window) |
| `atlas space` | Report duplicate and big files (read-only; act from the window) |
| `atlas browsers` | List notification sites and extensions (read-only; act from the window) |
| `atlas check-url LINK` | Check a link without opening it (also `atlas link`) |
| `atlas scan FILE_OR_FOLDER...` | Check files right now (add `--quarantine` to act on bad ones) |
| `atlas history` | Recent verdicts |
| `atlas quarantine` | List quarantined files |
| `atlas restore ID` | Put a quarantined file back (asks first) |
| `atlas config` | Show settings and where they live |
| `atlas autostart on/off` | Start Atlas in the tray at sign-in |
| `atlas context-menu on/off` | Add or remove "Scan with Project Atlas" in Explorer's right-click menu |
| `atlas browser-extension on/off` | Connect or disconnect the browser extension's helper |

Only one copy of Atlas protection (tray or `guard`) runs at a time.

## Where things live

- Settings: `%APPDATA%\ProjectAtlas\config.json` (watched folders, thresholds, uploads, startup-check interval)
- History, cache, quarantine, backups, log: `%LOCALAPPDATA%\ProjectAtlas\`
- API key: Windows Credential Manager, entry `ProjectAtlas`

**With Microsoft Store Python**, Windows keeps a Store app's AppData files in a private folder, so both of those live under `%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\` instead (`Roaming\ProjectAtlas` and `Local\ProjectAtlas`). Atlas detects this and uses that real location, so the tray's *Open...* items and the right-click icon work. `atlas config` prints the exact folders.

## Privacy

`upload_unknown_files` is **off** by default. Files uploaded to VirusTotal can be downloaded by every VirusTotal Intelligence subscriber, so only turn it on if you're comfortable with that for everything in your watched folders. Download links are stored and shown without their query strings, which often hold temporary access tokens.

## Development

To work on Atlas from a clone instead of the installer:

```powershell
git clone https://github.com/frankiedoos12-a11y/project-atlas.git
cd project-atlas
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

A clone gets no Start menu entries and no `atlas` on PATH. Run its programs by path, from inside the `project-atlas` folder:

```powershell
.\.venv\Scripts\atlas.exe set-key          # once
.\.venv\Scripts\atlas.exe autostart on     # optional: start this copy at sign-in
.\.venv\Scripts\atlas-tray.exe             # start protection in the tray
.\.venv\Scripts\atlas-gui.exe              # open the window
.\.venv\Scripts\python.exe -m pytest -q    # run the tests
```

Don't run an installed copy and a clone at the same time. Only one copy's protection runs, and the right-click menu and browser helper point at whichever copy switched them on last.

## License

Project Atlas is free software under the [GNU General Public License v3.0 or later](LICENSE). You can use, study, share and change it; if you share a changed version, you share its source under the same license.

## Roadmap

- Publish the browser extension to the Chrome Web Store and Edge Add-ons (no Developer mode needed)
- Android app (Pixel 6 Pro): share-to-scan and installed-app audit
