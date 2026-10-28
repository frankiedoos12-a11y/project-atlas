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
2. **Traced** to where it came from. Windows tags downloads with a "Mark of the Web" that records the download link and the page it was on, and Atlas checks both sites on VirusTotal too: their detections, **how old they are** and **how security vendors categorise them**. Fake-download and scam sites are usually registered only days or weeks before they're used, so a site under 30 days old is a warning even before any engine flags it (big, popular sites are exempt). Only the site name is sent for the page, never its full address.
3. **Signature-checked**. Windows verifies who signed it and whether it has been tampered with since.
4. **Judged**:

| Verdict | Meaning | What happens |
|---|---|---|
| Clean | No engines flagged it | Nothing (logged) |
| Unknown | VirusTotal has no results for it, it can run code, and it isn't validly signed | Warning pop-up |
| Suspicious | A few engines flagged it, its signature is broken, or a site involved has a bad reputation, is brand new, or is listed by security vendors as phishing, malware or adware | Warning pop-up |
| Malicious | At least 3 engines flagged the file or its download link | Moved to quarantine + pop-up |

**Flagged files are explained, not just counted.** Instead of only "malicious, 12 engines", Atlas shows the malware family engines agree on (*Remcos (trojan)*) and, from VirusTotal's sandboxes, what the file actually does when run, in plain words: *lets an attacker control the PC remotely*, *steals passwords and browser cookies*, *sets itself up to start with Windows*, *turns off User Account Control*, *deletes backup snapshots*, *contacts u973.cantdown.su*. It also lists which sandboxes called it bad and which detection rules it matched. A clean program VirusTotal first saw only days ago gets a note too, since engines can take a few days to catch up with new malware.

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

- **Check a link before you open it.** Paste a link from an email, text or ad. Atlas never visits it. It asks VirusTotal about the exact link and its site, and spots scam tricks offline: a familiar name inside someone else's address (`paypal.com.account-verify.xyz`), look-alike foreign letters, an `@` hiding the real destination, bare IP addresses and link shorteners. It also warns about sites registered in the last 30 days and ones security vendors list as phishing, malware or adware. A single "suspicious" vote on a normal site is treated as noise. The tray's **Check link on clipboard** does the same from anywhere: copy a link, then click it.
- **Sites allowed to send notifications.** "Click Allow to prove you're not a robot" pages use this to push fake virus alerts and ads. Each site is checked on VirusTotal. **Block notifications** switches a site to *Block* (the browser must be closed; its settings file is backed up first to `%LOCALAPPDATA%\ProjectAtlas\backups`).
- **Extensions.** Flags the signs of adware: installed by another program from outside the store, forced on by a policy, loaded unpacked, or taking over your search engine, home page or new tab page. Store extensions bundled by a program you installed (Adobe Acrobat, Google Docs Offline) are noted, not flagged. **Open in browser to remove** jumps to that extension in the browser's own extensions page.

`atlas browsers` and `atlas check-url LINK` do the same from the console.

### Browser extension: check links as you open them

The **Project Atlas Link Checker** extension (Chrome, Edge, Brave) asks Atlas on your PC about every page before you use it. A dangerous or suspicious page (including a brand-new site, the kind malicious ads lead to) is replaced by a warning, with *Go back to safety* or *Continue anyway* (remembered until the browser restarts). The toolbar globe shows the current page's verdict, and right-clicking any link gives **Check link with Project Atlas**.

- **Your key never enters the browser.** The extension talks to a small Atlas helper on your PC (Chrome's *native messaging*), which uses the key from Credential Manager.
- **Privacy:** pages you open are checked without their `?query` and `#fragment`, which often hold search terms or login tokens. Only links you right-click are checked in full. Addresses on your PC or home network (`192.168.x.x`, `localhost`, `router`, `*.local`) are never sent anywhere.
- Unknown sites aren't blocked, only marked `?` on the globe, so new and small sites still open normally.

**Set up:** the installer connects the helper (`atlas browser-extension on`). Then, once per browser: open `chrome://extensions` (or `edge://extensions`), turn on **Developer mode**, click **Load unpacked**, paste `%LOCALAPPDATA%\Programs\ProjectAtlas\extension` into the folder box's address bar, press Enter and click **Select Folder**. Atlas's own ad-spam finder recognizes it, so it isn't flagged for being loaded unpacked.

## 6. Running now: programs and network

Is anything bad running right now? The **Running now** tab answers it two ways. Both only look; nothing is stopped or blocked unless you press **End program...** (which asks first).

- **Programs.** Atlas hashes the file behind every running program and looks it up on VirusTotal. Tick **Include DLLs** to also check the DLLs they've loaded from outside the Windows folder: malware often hides as a DLL next to a legitimate program. (The first check with DLLs can take a few minutes; hashes are remembered, so later ones are quick.) A file VirusTotal has never seen is fine if it's validly signed, and marked *Unknown* if not. Flagged files get the same plain-words explanation as downloads.
- **Network connections.** Every connection a program has open to an internet address (not your home network), with the program's name, who owns the address (*Google LLC*, *Akamai*, *Bad Hosting Ltd, NL*), and whether VirusTotal flags it. Addresses are shared by many sites, so like websites they need several engines before they count as suspicious. On Windows versions that allow it, Atlas also checks the sites the PC looked up recently (the DNS cache); recent Windows 11 builds only show that list to administrators, and Atlas says so when it can't see it.

The tray repeats both checks every hour (`running_check_minutes`; `0` = only when you ask) and pops up an alert the first time something flagged is running or being talked to. Unknown programs are listed in the tab rather than popped up. `atlas running` (`--dlls`) and `atlas network` do the same from the console.

**New programs, as they start.** Between those hourly checks, the tray looks up each program the moment it starts and alerts you if VirusTotal flags it (`watch_new_programs`). Each program file is looked up once until it changes, so everyday programs cost no lookups after the first time.

**Ask Defender.** Select a file in *Running now*, *Installed* or the right-click scan window and press **Ask Defender** for a second opinion from Microsoft Defender's own scanner. It only reports; Defender is told not to touch the file. `atlas second-opinion FILE` does the same.

## 7. Protection: Defender and hijacked settings

The **Protection** tab checks the settings malware and adware change so they can get in or steer your browsing:

- **Defender.** Real-time protection, tamper protection, behaviour monitoring, how old the virus definitions are, and whether *Potentially unwanted app blocking* is on (it's off by default on many PCs, and it's the setting that stops adware and bundled junk). From Defender's own log for the last 30 days: exclusions that were added (malware's favourite way to hide), protection being switched off, tamper protection blocking a change, and what Defender found. Exclusions set by Windows policy are flagged too. If another antivirus is in charge, Atlas says so and leaves it alone.
- **Browser start page and search engine**, for every Chrome, Edge, Brave, Opera and Firefox profile. Known hijackers (Genieo, Conduit, Trovi, OneLaunch...) and search sites that come through a "partner" code are flagged; unusual search engines and start pages are looked up on VirusTotal. Google, Bing, DuckDuckGo and the like are fine.
- **Browser policies.** Settings forced by a policy can't be changed back in the browser. Home PCs normally have none.
- **Proxy.** A proxy or proxy script routes your web traffic through someone else's server.
- **Hosts file.** Lines that block security or update sites, or that send a site (your bank, say) to a different address.
- **DNS servers.** Known public resolvers and your router are fine; anything else is looked up on VirusTotal, with its owner shown.

Each problem has a button. Most open the right page in Windows Security, Settings or the browser, so you make the change. Atlas changes two things itself, after asking and with a backup saved in the `backups` folder first: it can turn off your account's proxy setting, and remove a browser policy set in your account. The hosts file opens in Notepad as administrator for you to edit.

The tray re-runs these checks every hour (`system_check_minutes`) and pops up an alert when a new problem appears. The first run just notes what's already there; the tray menu shows how many things need a look. `atlas protection` prints the same list.

## 8. Installed programs

The **Installed** tab lists what's installed, the same list as *Settings > Apps*. Atlas looks up each program's main file on VirusTotal and recognises well-known adware and "potentially unwanted programs" by name (OneLaunch, Wave Browser, Web Companion, Restoro, PC optimisers...). When the engines' consensus is *adware* or *PUA*, it's shown as **UNWANTED** rather than malware: a nuisance that's best removed, not a break-in. **Uninstall...** runs the program's own uninstaller after asking you. `atlas installed` prints the list.

## Updates and VirusTotal usage

The window's header shows how many VirusTotal lookups Atlas has made today and this month (a free key allows 500 a day; answers Atlas already has don't count). `atlas quota` breaks it down.

Once a day the tray checks GitHub for a newer version (`check_for_updates`). When there is one, it tells you, and in a copy set up by the installer the tray menu and the window's **Update now** button re-run the installer in a window you can watch. Settings, history and your key are kept. `atlas update` checks from the console, and `atlas update --now` updates.

## The Atlas window

Open it from **Start menu > Project Atlas**, by clicking the tray globe, or with `atlas gui`. It has nine tabs:

- **Startup items**: everything set to start automatically, colour-coded by verdict, with a filter (*Not Microsoft*, *Needs a look*, *Microsoft*, *Leftovers*, *Everything*), a search box, sortable columns, and a details panel showing publisher, file, registry location and why Atlas judged it that way. Buttons open the file's folder or its VirusTotal page, and **Switch off / Switch on** the item. **Check now** re-runs a full check.
- **Running now**: running programs (and DLLs) and network connections, checked with VirusTotal (see above).
- **Installed**: installed programs, with adware and unwanted software called out, and **Uninstall...** (see above).
- **Protection**: Defender, browser start pages and search, proxy, hosts file and DNS, each with a fix button (see above).
- **Activity**: every file Atlas has checked, newest first, with where it was downloaded from.
- **Cleanup**: finds junk and leftovers with no home (see below). Tick what to remove, then **Clean selected**.
- **Disk space**: duplicate files and big files, with *Recycle*, *Move to folder…* and *Free up space* (see above).
- **Browsers**: link checker, notification spam and extensions (see above).
- **Quarantine**: files Atlas moved out of the way, with **Restore** (asks first).

The header shows whether protection is running, whether your VirusTotal key is connected, today's VirusTotal lookups, and when an update is available.

## The tray icon

The globe is **blue** while protecting, **grey** while paused, and **red** after an alert (until you choose *Clear alert*). Left-click it to open the Atlas window, or right-click it for:

- Open Project Atlas
- *Protection: N thing(s) need a look* (when there are any) and *Update to Project Atlas X* (when there's an update)
- Pause protection
- Check startup items now
- Check running programs and network now
- Check Defender, browsers and network settings now
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
| `atlas running` | Check running programs with VirusTotal (`--dlls` to include loaded DLLs, `--all` to list clean ones too) |
| `atlas network` | Check the internet addresses programs are connected to (`--all` to list clean ones too) |
| `atlas protection` | Check Defender, browser start pages and search, proxy, hosts file and DNS (`--all` to list what's fine too) |
| `atlas installed` | Check installed programs for adware and unwanted software (`--all` to list every program) |
| `atlas second-opinion FILE...` | Ask Microsoft Defender to scan files (report only) |
| `atlas quota` | VirusTotal lookups Atlas made today and this month |
| `atlas update` | Check for a newer version (`--now` to update an installed copy) |
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

- Settings: `%APPDATA%\ProjectAtlas\config.json` (watched folders, thresholds, uploads, how often the startup, running and Protection checks run, new-program alerts, update checks)
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
