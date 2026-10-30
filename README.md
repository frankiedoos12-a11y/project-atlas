# Project Atlas

VirusTotal-powered protection for Windows 11. It runs **alongside** Windows Defender, not instead of it. No ads, no upsells, and all data stays on your PC.

## Install

**[Download ProjectAtlas-Setup.exe](https://github.com/frankiedoos12-a11y/project-atlas/releases/latest/download/ProjectAtlas-Setup.exe)** and open it. It needs no administrator rights and no Python, works on Windows 10 and 11 (64-bit), and puts **Project Atlas** on your desktop and in the Start menu.

1. Windows may say **"Windows protected your PC"**, because Atlas is new and isn't code-signed yet. Click **More info**, then **Run anyway**.
2. Pick the options you want (all are on by default) and click **Install**. *Keep protection running* asks for administrator approval once: see [The Atlas service](#the-atlas-service).
3. Atlas opens. Click **Add VirusTotal key...** at the top right and follow the steps: the key is free, and each PC keeps its own in Windows Credential Manager.

- **Update:** when there's a new version, Atlas offers **Update now** (in the window and the tray menu). Or download and run the newest setup again. Settings, history and your key are kept.
- **Uninstall:** Settings > Apps > Installed apps > **Project Atlas** > Uninstall. Your settings, history, quarantine and key are kept in case you reinstall.

### Or install with PowerShell

This way installs Python and adds the `atlas` command to every terminal. On any Windows 10 or 11 PC, open **PowerShell** (Start menu, type *PowerShell*, press Enter; no administrator rights needed) and paste:

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

The setup (`ProjectAtlas-Setup.exe`) puts **Project Atlas** on the desktop too. It doesn't add `atlas` to terminals or a separate tray shortcut: the window's **Start protection** button starts the tray, and the commands are in `%LOCALAPPDATA%\Programs\Project Atlas\atlas.exe`.

The tray and the window never run as administrator. If you start them from an administrator terminal, they restart themselves with your normal rights. Windows blocks dragging files into an administrator window, and the window opens untrusted files such as emails. The few features that need administrator rights ask Windows for them: the deep check, Defender's full and offline scans, and Defender's extra protection.

### The Atlas service

Protection runs in the tray, so it used to stop if someone chose *Quit*, ended Atlas in Task Manager, or it crashed. The installer's **Keep protection running** option (on by default, needs administrator approval once) adds a small Windows service that prevents that:

- Every 15 seconds it checks that each signed-in person who uses Atlas has the tray running. If not, it starts the tray again within about a minute, and the tray says it was restarted.
- **Quit** then asks for an administrator's approval (the Windows prompt). Without it, Atlas keeps running: choose *Pause protection for an hour* instead. An approved Quit lasts until that person signs out.
- *Start with Windows* is always on while the service is installed.
- The service does nothing else. The checks stay in the tray with your normal rights, so Atlas never opens a download or an email with full control of the PC. The service's own program is copied to `C:\Program Files\Project Atlas Service`, which only administrators can change, and it always starts the tray with the signed-in person's own rights.
- It uses almost no memory or processor time: one quick look every 15 seconds.
- Commands: `atlas service status`, and `atlas service install` or `atlas service uninstall` (both ask for an administrator). Uninstalling Atlas removes the service too.

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
| Privacy: browsing history (Chrome, Edge, Brave, Opera) | No | Deleted for good: visited sites and new-tab shortcuts. Bookmarks, passwords and saved form data are kept. Locked while that browser is open. Firefox keeps history with bookmarks, so clear it in Firefox (Ctrl+Shift+Delete) |
| Privacy: cookies and site data (those browsers and Firefox) | No | Deleted for good. This **signs you out of every website** in that browser, and clears trackers too |
| Privacy: recent files list | No | Clears File Explorer's list of files you opened lately. The files themselves are untouched |

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

### When Atlas gets it wrong

Atlas's own guesses (a brand name on someone else's domain, look-alike letters, a brand-new domain) are sometimes wrong. Each brand already knows its other real domains (Outlook's sign-in at `outlook.live.com` is Microsoft's), and there are three more ways out:

- **Always trust this site** (on the browser warning page, and in the link checker) trusts the whole domain on this PC: `outlook.live.com` trusts `live.com`. Atlas skips its own guesses about it but still asks VirusTotal, so a trusted site that turns malicious is still flagged. **Trusted sites...** in the link checker lists them, with **Remove** (`trusted_sites` in the settings).
- **Report a mistake** (on the browser warning page, the link checker, the scan window and the threat hunt) opens a filled-in *Wrong warning* report on GitHub for you to read and send. It holds only the site's name (never the full address), or the file's name and SHA-256, what Atlas said and why, and the Atlas version; your user folder is replaced by `%USERPROFILE%`. Nothing is sent until you press *Create*.
- **The shared allow-list.** When a report turns out to be a mistake, the site goes into [`allowlist.json`](allowlist.json) in this repository. Every copy of Atlas downloads it once a day and trusts what's on it the same way, with no new release needed (`shared_allowlist` turns this off).

### Browser extension: check links as you open them

The **Project Atlas Link Checker** extension (Chrome, Edge, Brave) asks Atlas on your PC about every page before you use it. A dangerous or suspicious page (including a brand-new site, the kind malicious ads lead to) is replaced by a warning, with *Go back to safety*, *Continue anyway* (remembered until the browser restarts), *Always trust this site* and *Report a mistake* (see above). The toolbar globe shows the current page's verdict, and right-clicking any link gives **Check link with Project Atlas**.

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

## 7. Protection: Defender, updates, remote access and hijacked settings

The **Protection** tab checks the settings malware and adware change so they can get in or steer your browsing:

- **Defender.** Real-time protection, tamper protection, behaviour monitoring, how old the virus definitions are, and whether *Potentially unwanted app blocking* is on (it's off by default on many PCs, and it's the setting that stops adware and bundled junk). From Defender's own log for the last 30 days: exclusions that were added (malware's favourite way to hide), protection being switched off, tamper protection blocking a change, and what Defender found. Exclusions set by Windows policy are flagged too. If another antivirus is in charge, Atlas says so and leaves it alone.
- **Extra protection Windows leaves off.** Cloud-delivered protection and block at first sight should be on. Defender also has *attack surface reduction* rules and *network protection*, which stop what most malware does first: Office macros and email attachments starting programs, scripts downloading programs, passwords being read out of memory, and dangerous sites in every browser. Windows Home has no switch for them, so **Turn on...** switches on 14 rules that suit a home PC (through Windows' own administrator prompt), and **Turn off again...** undoes it. Atlas also shows whether SmartScreen (Windows and Edge) and Smart App Control are on.
- **Software updates.** Programs with a newer version, found with winget (built into Windows), and when Windows last installed an update or is waiting for a restart. Outdated programs whose maker appears in CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (flaws attackers are using right now) are marked **Update soon**, with the CVEs. **Update** runs winget in a window you can watch. When more than three other programs have updates, they're one row with **Update all**.
- **Remote access.** AnyDesk, TeamViewer, ScreenConnect, Quick Assist, RustDesk and 22 other programs that let someone see and control the PC. They're legitimate, but they're how tech-support scams start: a caller or pop-up talks you into installing one. Atlas warns when one is running (with **End it**) or was downloaded in the last month, and notes installed ones. The tray pops up the moment one starts. If you use one on purpose, press **It's mine** and Atlas stays quiet about it (`trusted_remote_tools`).
- **Disk health.** Drives Windows says are failing or wearing out. The deep check adds wear, temperature and read errors.
- **Browser start page and search engine**, for every Chrome, Edge, Brave, Opera and Firefox profile. Known hijackers (Genieo, Conduit, Trovi, OneLaunch...) and search sites that come through a "partner" code are flagged; unusual search engines and start pages are looked up on VirusTotal. Google, Bing, DuckDuckGo and the like are fine.
- **Browser policies.** Settings forced by a policy can't be changed back in the browser. Home PCs normally have none.
- **Proxy.** A proxy or proxy script routes your web traffic through someone else's server.
- **Hosts file.** Lines that block security or update sites, or that send a site (your bank, say) to a different address.
- **DNS servers.** Known public resolvers and your router are fine; anything else is looked up on VirusTotal, with its owner shown.

Each problem has a button. Most open the right page in Windows Security, Settings or the browser, so you make the change. Atlas changes a few things itself, only after asking: it can turn off your account's proxy setting and remove a browser policy set in your account (with a backup saved in the `backups` folder first), switch Defender's extra protection on or off, start program updates, and end a running remote-access program. The hosts file opens in Notepad as administrator for you to edit.

The tray re-runs these checks every hour (`system_check_minutes`) and pops up an alert when a new problem appears. The first run just notes what's already there; the tray menu shows how many things need a look. `atlas protection` prints the same list.

**Health score.** The Protection checks and the threat hunt add up to one number from 0 to 100, shown on the window's Home page and in the tray menu: 90 and up is *Good*, 60 and up *Fair*, below that *Needs attention*. Things that need a look cost the most (more for Defender, remote access and threat-hunt findings), several in the same area cost less each, and notes cost a little.

**Weekly report.** Once a week the tray writes a short report and pops up a summary: the health score and how it moved, what's new, what got fixed, and what Atlas did (files checked, flagged and quarantined, VirusTotal lookups, space cleaned). It's a page in `%LOCALAPPDATA%\ProjectAtlas\reports` that stays on the PC. **Weekly report** on Home (or **Write one now** under History > Weekly reports), or `atlas report`, writes one now. Turn it off with `weekly_report`.

**Check a password...** tells you whether a password has appeared in a data leak, using Have I Been Pwned. The password never leaves the PC: Atlas sends only the first 5 characters of its SHA-1 hash, and nothing is saved. `atlas password-check` does the same.

Files VirusTotal flags now also show VirusTotal's own AI analysis (*Code Insight*, and a summary of what threat reports say about the file), when it has one.

### Full scan

The **Full scan** tab checks every program file on your drives (programs, DLLs, drivers and scripts) with VirusTotal, riskiest places first: your user folders, Downloads, Temp and ProgramData, then odd folders, then Program Files and Windows, newest files first. A free VirusTotal key does 500 lookups a day and 4 a minute, and a PC has tens of thousands of program files, so each run spends up to `full_scan_lookups` new lookups (200) and reuses answers it already has. Run it again another day and it carries on where it stopped. It runs at low priority so the PC stays quick, skips online-only OneDrive files (they'd be downloaded), and only looks: **Quarantine...** and **Ask Defender** are buttons. `atlas full-scan` does the same in the console.

**Defender full scan...** starts Microsoft Defender's own full scan, and **Defender offline scan...** restarts the PC to scan before Windows starts, where hidden malware can't fight back. Both ask Windows for administrator permission.

### Scam check

Got an email, text or pop-up you're not sure about? Paste it into **Online safety > Message and link check** (or `atlas scam-check`). Atlas looks for the usual scam tricks and explains each one it finds, quoting the words: asking for remote access, gift cards, crypto or wire payments, codes or passwords, "call this number", fake invoices and renewals, threats from the "police" or "IRS", virus scares, fake security pop-ups ("Your PC is blocked, call Microsoft"), blackmail, prizes, unpaid tolls and parcels, secrecy and pressure. Every link in the message is checked like the link checker does. It answers *Looks like a scam*, *Be careful* or *Nothing obvious found*. Rules only, no AI service: the message stays on the PC, and only its links go to VirusTotal.

**Screenshots.** A pop-up or a text message is often easier to screenshot than to copy: press Win+Shift+S, then **Paste**. Atlas reads the words with Windows' own text recognition, on the PC, and checks them the same way. **Open email or screenshot...** reads a picture file too (a phone screenshot you've copied over).

**Email files.** Pasting loses what gives an email away, so open the email itself: drop an `.eml` or `.msg` file on the message box, click **Open email or screenshot...**, or right-click the file > *Scan with Project Atlas*. To get the file: in Outlook on the PC, drag the email to the desktop; in Gmail, *⋮ > Download message*; in Outlook on the web, *⋯ > Save > Save as*. Besides the wording, Atlas checks:

- **Links that aren't what they say:** the text shows `microsoft.com` but the link goes elsewhere (Outlook Safe Links and Google redirects are unwrapped first; newsletter tracking links are left alone). Every real link target is checked like the link checker does.
- **The sender:** a display name like *Microsoft Support* or *PayPal* sent from a domain that isn't the company's, or from a free Gmail/Outlook address, and a *Reply-To* that sends your answer somewhere else.
- **Sender checks:** whether the email failed the SPF, DKIM or DMARC checks your mail provider recorded when it arrived.
- **The sender's domain:** brand-new domains and ones security vendors list as phishing.
- **Attachments:** risky kinds (programs, scripts, HTML and SVG pages, disk images) and each attachment's SHA-256 on VirusTotal. Attachments are never opened or saved.

Only links, the sender's domain and attachment fingerprints go to VirusTotal; the email itself stays on the PC.

## 8. Installed programs

The **Installed** tab lists what's installed, the same list as *Settings > Apps*. Atlas looks up each program's main file on VirusTotal and recognises well-known adware and "potentially unwanted programs" by name (OneLaunch, Wave Browser, Web Companion, Restoro, PC optimisers...). When the engines' consensus is *adware* or *PUA*, it's shown as **UNWANTED** rather than malware: a nuisance that's best removed, not a break-in. **Uninstall...** runs the program's own uninstaller after asking you. `atlas installed` prints the list.

## 9. Threat hunt

A hash lookup can only judge files. The **Threat hunt** tab looks for what it can't see:

- **Suspicious command lines.** Attacks often run inside Windows' own clean programs, so Atlas reads how each one was started and flags the giveaways. The rules follow the open Sigma and LOLBAS projects, and each finding names its MITRE ATT&CK technique. Examples:
  - encoded or hidden PowerShell, and PowerShell downloading and running code
  - commands pasted into the Run box by fake CAPTCHA ("ClickFix") pages
  - `mshta`, `rundll32`, `regsvr32`, `certutil` and `bitsadmin` fetching or running code
  - Word, Outlook or a PDF reader starting a shell
  - backups being deleted, the firewall or Defender being switched off, new administrators
  - a "svchost.exe" running from outside the Windows folder

  The tray also checks every new program's command line the moment it starts and alerts you, even without a VirusTotal key.
- **Root certificates.** Every trusted root in your account and the machine is compared with Microsoft's own trusted-root list, which Windows keeps up to date. Known spying certificates (Superfish, eDellRoot...), certificates Microsoft has blocked and recently added unknown roots need a look. Antivirus web shields, debugging proxies and government roots (DoD InstallRoot) are named for what they are.
- **Drivers and services.** Loaded drivers are matched against the [LOLDrivers](https://www.loldrivers.io) list of known-vulnerable and malicious drivers (downloaded weekly). Atlas also shows whether Microsoft's vulnerable driver blocklist and Memory integrity are on. Drivers and services installed in the last 30 days are flagged when they run a script or a program from a user folder, or an unsigned program from ProgramData.
- **Open doors.** Programs accepting connections from the network, with remote-access tools (AnyDesk, TeamViewer, ScreenConnect, NetSupport...) called out. Atlas checks that Windows Firewall is on, and lists inbound firewall rules that let in programs from user folders, or programs that are gone.
- **The registry.** The Startup items tab covers the Run keys, services, Winlogon and IFEO. The threat hunt reads the rest of the well-known hiding places and the settings attackers loosen, all without administrator rights:
  - *Hijacks:* per-user COM objects that override a Windows component, COM scriptlets loaded from the web, administrator-prompt (UAC) bypass keys (`ms-settings`, `mscfile`, `Folder`, wsreset...) and changed `.exe`/`.lnk` file types
  - *Other ways to start:* Command Processor AutoRun, Active Setup, AppInit and AppCert DLLs, silent process exit monitors, the crash debugger, netsh helpers, print monitors, time providers, the screensaver, logon scripts, the .NET profiler hook, the "Office test" DLL, and files in Word's and Excel's startup folders
  - *Passwords:* unknown LSA authentication, security and notification packages (password filters), WDigest keeping passwords readable in memory, and whether LSA protection is on
  - *Office:* "enable all macros", macros from the internet allowed by policy, Protected View switched off, and trusted locations in Downloads, the Desktop, Documents or a network share (Word, Excel, PowerPoint, Outlook and the rest, set by you or by a policy)
  - *UAC and Remote Desktop:* UAC off or set to never ask, no secure desktop, and Remote Desktop on, especially without Network Level Authentication

  Each finding says when its key last changed. Atlas also remembers every value it watches: when one appears or changes, the tray alerts you once and the change stays listed under "Registry changes" for a week. Each change shows the program it now runs, who signed it and what VirusTotal says, and the buttons open its folder, ask Defender, open its VirusTotal page or open the key in **Registry Editor**. A change where only the version moved (Chrome's `155.0...` folder becoming `156.0...`) to a signed program VirusTotal calls clean is a software update, so it's listed as a note instead. Files these keys point to are looked up on VirusTotal, and their hashes are matched against GTI.
- **Programs in user folders.** Programs running from AppData, Temp, Downloads or ProgramData that aren't validly signed. These are louder when they run from Temp or Downloads or are less than a week old. Atlas also finds programs hidden in another file's invisible "alternate data stream".

Programs these checks turn up are looked up on VirusTotal. With a VirusTotal Enterprise / Google Threat Intelligence key, every loaded driver is looked up too.

**Google Threat Intelligence.** With a GTI key, Atlas downloads the indicators from Google's own threat reports about Windows from the last 90 days (`gti_days`), once a day: file hashes, domains, URLs, IP addresses and ATT&CK techniques. It then matches them on this PC, with no extra lookups, against:
- every file Atlas has hashed (running programs, DLLs, drivers, startup items, downloads)
- the sites in your browsers' history
- download sources
- live connections

A match shows the report and links to it. Command-line findings say which recent GTI reports use the same technique, and flagged files list the GTI reports and threat actors that mention them. The reports stay on your PC and are never shared. On a key without GTI, all of this switches itself off. `atlas gti sync` downloads new reports now.

**Deep check (administrator).** Some things Windows only shows an administrator. **Deep check (administrator)...** asks Windows for permission and starts a small collector that only reads:
- Defender's exclusion list
- the DNS cache (matched against GTI and VirusTotal)
- the Security log: failed sign-ins, new accounts, new administrators, the log being cleared
- the command lines of system processes
- WMI event subscriptions

It needs no VirusTotal key, so it works even if Windows asks for a different administrator account.

The tray runs the threat hunt with the Protection checks every hour and alerts you to anything new. `atlas hunt` prints it (`--admin` adds the deep check).

## 10. Home network: the router, the Wi-Fi and every device

**Protection > Home network** lists every device on your home network: the router, this PC, TVs, phones, consoles and cameras. It also checks the things that protect all of them. The rule is *protect, not disturb*: Atlas never signs in to the router, never floods or sweeps the network, and never scans a device on its own.

- **Which networks:** only a network Windows calls *Private*, or one you confirmed with **This is my home network**. Windows 11 marks new networks *Public*, homes included, so Atlas asks first. It never looks at a café's or hotel's network.
- **Devices:** each device shows its name and model, maker, address, and when it was first and last seen. The tray tells you once when a new device joins.
- **Names and models come from what devices announce about themselves:**
  - **Bonjour:** Apple devices, Chromecasts, printers, speakers and smart-home gear. For example: *Ireland TV, AppleTV11,1*.
  - **UPnP:** TVs, consoles and media boxes. For example: *Roku Ultra, Roku 4670RW*.
  - **Windows PCs:** their name.

  Phones and tablets use made-up hardware addresses and often stay quiet, so they show as *Phone, tablet or laptop*; your router's app shows their names.
- **Identify this device:** for a mystery device, select it and click this button.
  - Atlas tries a normal connection to about 20 well-known ports on that one device and reads its web page's title, if it has one.
  - It then guesses, for example "Probably a printer" or "Probably an iPhone or iPad".
  - It only does this when you click, and only for the device you chose.
- **Wi-Fi security:**
  - No password, WEP, WPA or TKIP needs a look.
  - WPA2 (AES) is fine.
  - WPA3 is best.
- **UPnP:**
  - Atlas checks whether the router lets devices open doors to the internet by themselves.
  - If it does, Atlas lists each door.
  - A door to a camera, Remote Desktop, a router page or remote sign-in needs a look.
- **DNS:**
  - Atlas checks who answers your website lookups.
  - An unfamiliar provider is worth knowing about.
  - With a VirusTotal key, a flagged provider needs a look: someone may have changed the router's DNS setting.
- **The router:** Atlas recognises the brand from its sign-in page. It then gives a checklist to confirm in the router's app: the admin password, automatic updates, WPS and remote management. Atlas can't see these without signing in.
- **Is the router out of date?** Atlas can't see the firmware version without signing in, and it never updates the router itself: a failed update can leave the house offline. Instead:
  - When the router names its model (in UPnP or on its sign-in page), Atlas checks it against [CISA's list of flaws criminals are using](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
  - A listed model needs a look: update its firmware in the router's app. If CISA says the model is past end of life, the maker no longer fixes it, and Atlas suggests replacing it.
  - Gateways from your internet provider (Xfinity, AT&T, Verizon, Spectrum) are updated by the provider; you can't update them yourself.

Finding the devices takes about 20 seconds once a day: Atlas sends one tiny packet to each address on the network, then asks devices once to announce themselves. The rest of the day Atlas reads what Windows already knows, which takes a few seconds an hour. `atlas home` prints it (`--now` looks again). To switch it off, set `check_home_network` to `false` in the settings.

## Updates and VirusTotal usage

The window's header shows how many VirusTotal lookups Atlas has made today and this month (a free key allows 500 a day; answers Atlas already has don't count). `atlas quota` breaks it down.

**Without a VirusTotal key**, Atlas still works:
- **Programs:** Microsoft Defender checks every program it scans. Defender comes with Windows and needs no key or administrator rights. Defender is the PC's antivirus; Atlas adds a second opinion and never replaces it.
- **Unsigned downloads:** a program downloaded from the internet that isn't signed is marked *unknown*. Without VirusTotal, Atlas can't tell whether other people have run it safely.
- **View on VirusTotal:** it opens the file's or site's VirusTotal page in your browser, so you can look it up yourself. Only the site's name is sent, never the full link, because links can hold sign-in tokens.

The header shows which mode Atlas is in.

Once a day the tray checks GitHub for a newer version (`check_for_updates`). When there is one, it tells you, and the tray menu and the window's **Update now** button update Atlas: the app downloads the newest release's setup and runs it, and a copy set up by `install.ps1` re-runs that in a window you can watch. Settings, history and your key are kept. `atlas update` checks from the console, and `atlas update --now` updates.

## The Atlas window

Open it from **Start menu > Project Atlas**, by clicking the tray globe, or with `atlas gui`. A sidebar on the left keeps it tidy: **Home**, then five groups, each with a few tabs.

**Home** shows the health score (from the Protection checks and the threat hunt, run when the window opens; **Check again** re-runs them), quick actions (*Scan a file...*, *Check a message or link*, *Full scan*, *Clean up junk*, *Check a password...*, *Weekly report*) and the top things that need a look, each with its fix button and **Details**, which jumps to it on the Protection page. The sidebar shows how many things need a look next to *Protection*.

**Protection**
- **Checks**: Defender and its extra protection, SmartScreen, software and Windows updates, remote-access programs, disk health, browser start pages and search, proxy, hosts file and DNS, each with a fix button (see above).
- **Full scan**: every program file on the PC, a day's worth of lookups at a time, plus Defender's full and offline scans (see above).
- **Threat hunt**: command lines, root certificates, drivers, open ports, registry hiding places and settings, user-folder programs, threat-intel matches and the administrator deep check (see above).

**My PC**
- **Startup items**: everything set to start automatically, colour-coded by verdict, with a filter (*Not Microsoft*, *Needs a look*, *Microsoft*, *Leftovers*, *Everything*), a search box, sortable columns, and a details panel showing publisher, file, registry location and why Atlas judged it that way. Buttons open the file's folder or its VirusTotal page, and **Switch off / Switch on** the item. **Check now** re-runs a full check.
- **Running now**: running programs (and DLLs) and network connections, checked with VirusTotal (see above).
- **Installed**: installed programs, with adware and unwanted software called out, and **Uninstall...** (see above).

**Online safety**
- **Message and link check**: paste a message to see whether it looks like a scam (see above).
- **Browsers**: link checker, notification spam and extensions (see above).
- **Passwords**: whether a password has appeared in a data leak (see above).

**Clean up**
- **Cleanup**: finds junk, leftovers with no home, and privacy traces (see above). Tick what to remove, then **Clean selected**.
- **Disk space**: duplicate files and big files, with *Recycle*, *Move to folder…* and *Free up space* (see above).

**History**
- **Activity**: every file Atlas has checked, newest first, with where it was downloaded from.
- **Quarantine**: files Atlas moved out of the way, with **Restore** (asks first).
- **Weekly reports**: the reports the tray wrote, with **Open** and **Write one now**.

The header shows whether protection is running, whether your VirusTotal key is connected, today's VirusTotal lookups, and when an update is available.

## The tray icon

The globe is **blue** while protecting, **grey** while paused, and **red** after an alert (until you choose *Clear alert*). Left-click it to open the Atlas window, or right-click it for:

- Open Project Atlas
- *Health score: N/100* (after the first hourly check), *Protection and threat hunt: N thing(s) need a look* (when there are any) and *Update to Project Atlas X* (when there's an update)
- Pause protection (*for an hour* while the Atlas service is installed)
- Check startup items now
- Check running programs and network now
- Check Defender, browsers, network settings and threat hunt now
- Scan watched folders now
- Check link on clipboard
- Open activity log / quarantine folder / settings file
- Start with Windows (always on while the Atlas service is installed)
- "Scan with Project Atlas" in right-click menu
- Quit (needs an administrator's approval while the Atlas service is installed)

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
| `atlas protection` | Check Defender, updates, remote access, disk health, browser start pages and search, proxy, hosts file and DNS, and show the health score (`--all` to list what's fine too) |
| `atlas scam-check [FILE]` | Is this message a scam? Paste it, or give a text file holding it |
| `atlas full-scan` | Check every program file on the PC, riskiest first (`--budget N` new VirusTotal lookups; default `full_scan_lookups`) |
| `atlas report` | Write this week's report now and open it (`--no-open` to just save it) |
| `atlas password-check` | Check whether a password has appeared in a data leak (only 5 characters of its hash leave the PC) |
| `atlas installed` | Check installed programs for adware and unwanted software (`--all` to list every program) |
| `atlas second-opinion FILE...` | Ask Microsoft Defender to scan files (report only) |
| `atlas quota` | VirusTotal lookups Atlas made today and this month |
| `atlas update` | Check for a newer version (`--now` to update an installed copy) |
| `atlas home` | Your router, Wi-Fi and the devices on your home network (`--now` looks again, `--json` for scripts) |
| `atlas hunt` | Command lines, certificates, drivers, open ports, user-folder programs and threat intel (`--admin` adds the deep check, `--all` lists what's fine too) |
| `atlas gti` | Google Threat Intelligence reports on this PC (`atlas gti sync` downloads new ones) |
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
| `atlas service status/install/uninstall` | The service that keeps the tray running (install and uninstall ask for an administrator) |
| `atlas context-menu on/off` | Add or remove "Scan with Project Atlas" in Explorer's right-click menu |
| `atlas browser-extension on/off` | Connect or disconnect the browser extension's helper |

Only one copy of Atlas protection (tray or `guard`) runs at a time.

## Where things live

- Settings: `%APPDATA%\ProjectAtlas\config.json` (watched folders, thresholds, uploads, how often the startup, running, Protection and threat hunt checks run, new-program alerts, update checks, Google Threat Intelligence, remote-access programs you use, sites you trust and the shared allow-list, the weekly report, full-scan lookups)
- History, cache, quarantine, backups, log: `%LOCALAPPDATA%\ProjectAtlas\`
- API key: Windows Credential Manager, entry `ProjectAtlas`

**With Microsoft Store Python**, Windows keeps a Store app's AppData files in a private folder, so both of those live under `%LOCALAPPDATA%\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\` instead (`Roaming\ProjectAtlas` and `Local\ProjectAtlas`). Atlas detects this and uses that real location, so the tray's *Open...* items and the right-click icon work. `atlas config` prints the exact folders.

## Privacy

`upload_unknown_files` is **off** by default. Files uploaded to VirusTotal can be downloaded by every VirusTotal Intelligence subscriber, so only turn it on if you're comfortable with that for everything in your watched folders. Download links are stored and shown without their query strings, which often hold temporary access tokens. The threat hunt reads your browsers' history only to match it against threat intel on this PC; history never leaves the PC, and neither do the Google Threat Intelligence reports downloaded with your key. The update check sends nothing about your PC: winget compares your programs against its catalog, and CISA's catalog is downloaded whole. The password check sends only 5 characters of the password's hash. The scam check sends only the message's links (to VirusTotal); for an email file also the sender's domain and attachment fingerprints, and screenshots are read on the PC by Windows' own text recognition. And the weekly report never leaves the PC. The shared allow-list is downloaded whole from GitHub, so it sends nothing about you, and *Report a mistake* sends nothing itself: it opens a report you read and send.

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

To build `ProjectAtlas-Setup.exe` yourself, install PyInstaller in the environment (`.\.venv\Scripts\python.exe -m pip install pyinstaller`) and [Inno Setup 6](https://jrsoftware.org/isinfo.php) (`winget install JRSoftware.InnoSetup`), then run `powershell -ExecutionPolicy Bypass -File packaging\build.ps1`. It writes `packaging\dist\ProjectAtlas-Setup.exe`. Pushing a tag such as `v0.10.0` builds it on GitHub and attaches it to a new release (`.github/workflows/release.yml`).

Don't run an installed copy and a clone at the same time. Only one copy's protection runs, and the right-click menu and browser helper point at whichever copy switched them on last.

## License

Project Atlas is free software under the [GNU General Public License v3.0 or later](LICENSE). You can use, study, share and change it; if you share a changed version, you share its source under the same license.

The device-maker list (`atlas/oui.txt.gz`) comes from Wireshark's [manuf file](https://www.wireshark.org/download/automated/data/manuf.gz) (GPL-2.0-or-later). Wireshark builds it from the IEEE registry.

## Roadmap

- Publish the browser extension to the Chrome Web Store and Edge Add-ons (no Developer mode needed)
- Android app (Pixel 6 Pro): share-to-scan and installed-app audit
