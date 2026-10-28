"""Windows toast notifications, with a console fallback."""

from __future__ import annotations

import logging

from atlas.scanner import ScanResult, Verdict

log = logging.getLogger(__name__)

TITLES = {
    Verdict.CLEAN: "Atlas: looks clean",
    Verdict.UNKNOWN: "Atlas: unknown file, be careful",
    Verdict.SUSPICIOUS: "Atlas: suspicious download",
    Verdict.MALICIOUS: "Atlas: malicious download blocked",
    Verdict.ERROR: "Atlas: could not check file",
}

AUTORUN_TITLES = {
    Verdict.CLEAN: "Atlas: new startup item",
    Verdict.UNKNOWN: "Atlas: unknown program set to start automatically",
    Verdict.SUSPICIOUS: "Atlas: suspicious startup item",
    Verdict.MALICIOUS: "Atlas: malicious startup item",
    Verdict.ERROR: "Atlas: could not check startup item",
}


def toast_body(result: ScanResult) -> str:
    lines = [result.path.name]
    if result.reasons:
        lines.append(result.reasons[0])
    details = [t for t in (result.signer_text, result.source_text) if t]
    if details:
        lines.append(" · ".join(details))
    if result.action:
        lines.append(result.action.capitalize())
    return "\n".join(lines)


def toast(title: str, body: str, link: str | None = None, loud: bool = False) -> None:
    try:
        from winotify import Notification, audio

        note = Notification(app_id="Project Atlas", title=title, msg=body[:250], duration="long")
        if loud:
            note.set_audio(audio.Default, loop=False)
        if link:
            note.add_actions(label="View on VirusTotal", launch=link)
        note.show()
    except Exception:  # winotify missing or toast failed: fall back to the log
        log.warning("%s | %s", title, body.replace("\n", " | "))


def _vt_link(result: ScanResult) -> str | None:
    return result.file_report.gui_link if result.file_report and result.file_report.found else None


def notify(result: ScanResult, show_clean: bool = False) -> None:
    if result.verdict is Verdict.CLEAN and not show_clean:
        return
    toast(TITLES[result.verdict], toast_body(result), _vt_link(result),
          loud=result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS))


def notify_autorun(entry, result: ScanResult, is_new: bool) -> None:
    lines = [f"{entry.name} ({entry.category}{'' if is_new else ', changed'})"]
    if result.reasons:
        lines.append(result.reasons[0])
    if result.signer_text and result.signer_text not in lines[-1]:
        lines.append(result.signer_text)
    lines.append(str(result.path))
    toast(AUTORUN_TITLES[result.verdict], "\n".join(lines), _vt_link(result),
          loud=result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS))
