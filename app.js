// app.js — CFL License Portal Frontend Logic

const API_BASE = "./api.php";

// ─── Utility ─────────────────────────────────────────────────────────────────

function showResult(el, msg, type = "error") {
  el.textContent = msg;
  el.className = `result ${type}`;
}

function hideResult(el) {
  el.className = "result hidden";
}

function setLoading(btn, loading) {
  const text = btn.querySelector(".btn-text");
  const loader = btn.querySelector(".btn-loader");
  if (!loader) {
    btn.disabled = loading;
    return;
  }
  text.style.display = loading ? "none" : "";
  loader.style.display = loading ? "flex" : "none";
  btn.disabled = loading;
}

// ─── Server ping ──────────────────────────────────────────────────────────────

async function pingServer() {
  const el = document.getElementById("server-status");
  if (!el) return;
  try {
    const r = await fetch(`${API_BASE}?action=ping`, { method: "GET" });
    if (r.ok) {
      el.textContent = "SERVER ONLINE";
      el.previousElementSibling.classList.add("pulse");
    } else throw new Error();
  } catch {
    el.textContent = "SERVER OFFLINE";
    el.previousElementSibling.classList.remove("pulse");
    el.previousElementSibling.classList.add("error");
  }
}

// ─── Login page ───────────────────────────────────────────────────────────────

const authBtn = document.getElementById("authBtn");
const keyInput = document.getElementById("licenseKey");
const pasteBtn = document.getElementById("pasteBtn");
const resultEl = document.getElementById("result");

if (authBtn) {
  authBtn.addEventListener("click", doLogin);
  if (keyInput)
    keyInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doLogin();
    });
}

if (pasteBtn) {
  pasteBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      keyInput.value = text.trim();
      keyInput.focus();
    } catch {
      showResult(resultEl, "Clipboard access denied — paste manually.", "warn");
    }
  });
}

async function doLogin() {
  const key = keyInput ? keyInput.value.trim() : "";
  if (!key) {
    showResult(resultEl, "Please enter a license key.", "warn");
    return;
  }

  hideResult(resultEl);
  setLoading(authBtn, true);

  try {
    const fd = new FormData();
    fd.append("action", "login");
    fd.append("user_key", key);

    const r = await fetch(API_BASE, { method: "POST", body: fd });
    const data = await r.json();

    if (data.success) {
      showResult(
        resultEl,
        `✓ AUTHENTICATED — Expires: ${data.expiry || "N/A"}`,
        "success",
      );
      keyInput.value = "";
    } else {
      showResult(
        resultEl,
        `✗ ${data.message || "Authentication failed."}`,
        "error",
      );
    }
  } catch (err) {
    showResult(resultEl, `Network error: ${err.message}`, "error");
  } finally {
    setLoading(authBtn, false);
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  pingServer();
});
