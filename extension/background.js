// Project Atlas Link Checker: asks Project Atlas on this PC about each page before you use it.
// The VirusTotal key stays in Windows Credential Manager; this extension only sees verdicts.

const HOST = "com.projectatlas.linkcheck";
const CACHE_MS = 30 * 60 * 1000;
const WARN = new Set(["malicious", "suspicious"]);
const BADGES = {
  malicious: ["!", "#c62828"], suspicious: ["!", "#d84315"], unknown: ["?", "#9a7400"],
  offline: ["off", "#777777"], error: ["", "#777777"], clean: ["", "#2e7d32"], skipped: ["", "#2e7d32"],
};

let port = null;
let nextId = 1;
const waiting = new Map(); // request id -> resolve
const cache = new Map(); // url -> {result, at}

function helperMissing(error) {
  return {
    verdict: "offline",
    reasons: [/not found/i.test(error || "")
      ? "Project Atlas's helper isn't set up on this PC. Run: atlas browser-extension on"
      : `Couldn't reach Project Atlas (${error || "no answer"})`],
  };
}

function connect() {
  try {
    port = chrome.runtime.connectNative(HOST);
  } catch (e) {
    port = null;
    return null;
  }
  port.onMessage.addListener((msg) => {
    const resolve = waiting.get(msg.id);
    if (resolve) {
      waiting.delete(msg.id);
      resolve(msg);
    }
  });
  port.onDisconnect.addListener(() => {
    const error = chrome.runtime.lastError && chrome.runtime.lastError.message;
    port = null;
    for (const resolve of waiting.values()) resolve(helperMissing(error));
    waiting.clear();
  });
  return port;
}

function ask(message) {
  return new Promise((resolve) => {
    if (!port && !connect()) return resolve(helperMissing("not found"));
    const id = nextId++;
    waiting.set(id, resolve);
    setTimeout(() => {
      if (waiting.delete(id)) resolve({ verdict: "error", reasons: ["Project Atlas took too long to answer"] });
    }, 20000);
    try {
      port.postMessage({ id, ...message });
    } catch (e) {
      waiting.delete(id);
      resolve(helperMissing(String(e)));
    }
  });
}

// Every page you open is checked without its ?query and #fragment (often search terms or tokens);
// a link you right-click is checked in full.
async function check(url, auto) {
  const key = auto ? url.split(/[?#]/)[0] : url;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.result;
  const result = await ask({ type: "check", url, auto });
  if (result.verdict !== "offline" && result.verdict !== "error") cache.set(key, { result, at: Date.now() });
  return result;
}

function pageFor(url, result, mode) {
  const params = new URLSearchParams({
    u: url, v: result.verdict, r: JSON.stringify(result.reasons || []), l: result.vt_link || "", m: mode,
    p: result.report || "",
  });
  return chrome.runtime.getURL(`warning.html?${params}`);
}

function setBadge(tabId, verdict) {
  const [text, color] = BADGES[verdict] || ["", "#777777"];
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
}

async function allowedThisSession(url) {
  const { allowed = [] } = await chrome.storage.session.get("allowed");
  try {
    return allowed.includes(new URL(url).host);
  } catch (e) {
    return false;
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  const { auto = true } = await chrome.storage.local.get("auto");
  if (!auto || (await allowedThisSession(details.url))) return;
  const result = await check(details.url, true);
  setBadge(details.tabId, result.verdict);
  await chrome.storage.session.set({ [`tab${details.tabId}`]: { url: details.url, ...result } });
  if (WARN.has(result.verdict)) {
    chrome.tabs.update(details.tabId, { url: pageFor(details.url, result, "block") }).catch(() => {});
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "atlas-check", title: "Check link with Project Atlas", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "atlas-check" || !info.linkUrl) return;
  const result = await check(info.linkUrl, false);
  chrome.windows.create({ url: pageFor(info.linkUrl, result, "result"), type: "popup", width: 620, height: 520 });
});

// The warning page's "continue anyway", and the popup's status questions.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "allow") {
    chrome.storage.session.get("allowed").then(({ allowed = [] }) => {
      allowed.push(msg.host);
      chrome.storage.session.set({ allowed }).then(() => reply({ ok: true }));
    });
    return true;
  }
  if (msg.type === "trust") {
    // "Always trust this site": Atlas saves it in its settings; forget cached verdicts for it.
    ask({ type: "trust", host: msg.host }).then((answer) => {
      if (answer.ok) {
        for (const key of cache.keys()) {
          try {
            const host = new URL(key).hostname;
            if (host === answer.site || host.endsWith(`.${answer.site}`)) cache.delete(key);
          } catch (e) {
            cache.delete(key);
          }
        }
      }
      reply(answer);
    });
    return true;
  }
  if (msg.type === "ping") {
    ask({ type: "ping" }).then(reply);
    return true;
  }
  if (msg.type === "check") {
    check(msg.url, false).then(reply);
    return true;
  }
  return false;
});
