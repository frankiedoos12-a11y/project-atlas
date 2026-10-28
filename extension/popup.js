const COLORS = { malicious: "var(--malicious)", suspicious: "var(--suspicious)", unknown: "var(--unknown)",
  clean: "var(--clean)" };

(async () => {
  const auto = document.getElementById("auto");
  const { auto: on = true } = await chrome.storage.local.get("auto");
  auto.checked = on;
  auto.addEventListener("change", () => chrome.storage.local.set({ auto: auto.checked }));

  const helper = document.getElementById("helper");
  const ping = await chrome.runtime.sendMessage({ type: "ping" });
  if (ping && ping.ok) {
    helper.textContent = `Connected to Project Atlas ${ping.version}` + (ping.key ? "" : " (no VirusTotal key set)");
  } else {
    helper.textContent = (ping && ping.reasons && ping.reasons[0]) || "Project Atlas isn't connected";
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  const saved = (await chrome.storage.session.get(`tab${tab.id}`))[`tab${tab.id}`];
  const page = document.getElementById("page");
  if (saved && saved.verdict) {
    page.textContent = saved.verdict.toUpperCase();
    page.style.color = COLORS[saved.verdict] || "";
    document.getElementById("page-reason").textContent = (saved.reasons || [])[0] || "";
  } else {
    page.textContent = "not checked";
  }
})();
