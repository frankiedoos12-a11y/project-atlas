// Shows a verdict: "block" mode replaces a flagged page; "result" mode answers a right-click check.
const params = new URLSearchParams(location.search);
const url = params.get("u") || "";
const verdict = params.get("v") || "error";
const mode = params.get("m") || "block";
const link = params.get("l");
let reasons = [];
try {
  reasons = JSON.parse(params.get("r") || "[]");
} catch (e) {
  reasons = [];
}

const TITLES = {
  malicious: "This site is dangerous",
  suspicious: "This site looks suspicious",
  unknown: "Project Atlas doesn't know this link",
  clean: "This link looks safe",
  skipped: "Not checked",
  offline: "Project Atlas isn't connected",
  error: "The check didn't finish",
};

document.body.dataset.verdict = verdict;
document.getElementById("title").textContent = TITLES[verdict] || verdict;
document.getElementById("url").textContent = url;
const list = document.getElementById("reasons");
for (const reason of reasons) {
  const li = document.createElement("li");
  li.textContent = reason;
  list.appendChild(li);
}
if (link) {
  const vt = document.getElementById("vt");
  vt.href = link;
  vt.hidden = false;
}

const back = document.getElementById("back");
if (mode === "block") {
  document.title = `Blocked: ${verdict}`;
  back.addEventListener("click", () => (history.length > 2 ? history.go(-2) : (location.href = "about:blank")));
  const go = document.getElementById("continue");
  go.hidden = false;
  go.addEventListener("click", async () => {
    let host = "";
    try {
      host = new URL(url).host;
    } catch (e) {
      return;
    }
    if (!confirm(`Open ${host} anyway? Project Atlas won't warn about it again until you restart the browser.`)) return;
    await chrome.runtime.sendMessage({ type: "allow", host });
    location.href = url;
  });
} else {
  back.textContent = "Close";
  back.addEventListener("click", () => window.close());
  if (verdict === "clean") {
    const open = document.getElementById("open");
    open.hidden = false;
    open.addEventListener("click", () => {
      chrome.tabs.create({ url });
      window.close();
    });
  }
}
