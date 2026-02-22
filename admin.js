// admin.js — CFL Admin Panel with Library Management

const API = "./api.php";
const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB

// ─── Custom Confirmation Dialog ────────────────────────────────────────────
function showConfirmDialog(message, title = "Confirm Action") {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
    `;

    const dialog = document.createElement("div");
    dialog.style.cssText = `
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
      max-width: 420px;
      width: 90%;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
      animation: slideInUp 0.3s ease forwards;
    `;

    dialog.innerHTML = `
      <div style="font-size: 1.4rem; font-weight: 600; color: var(--accent); margin-bottom: 16px; display: flex; align-items: center; gap: 8px; text-align: left;">
        <span style="font-size: 1.6rem;">⚠️</span>
        <span>${title}</span>
      </div>
      <div style="color: var(--text); margin-bottom: 24px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; text-align: center;">${message}
      </div>
      <div style="display: flex; gap: 12px; justify-content: flex-end;">
        <button class="confirm-cancel" style="
          padding: 10px 24px;
          border: 1px solid var(--border);
          background: var(--panel);
          color: var(--text);
          border-radius: 4px;
          cursor: pointer;
          font-family: var(--font-main);
          font-weight: 600;
          transition: all 0.2s ease;
        ">CANCEL</button>
        <button class="confirm-ok" style="
          padding: 10px 24px;
          border: 1px solid var(--success);
          background: var(--success);
          color: var(--bg);
          border-radius: 4px;
          cursor: pointer;
          font-family: var(--font-main);
          font-weight: 600;
          transition: all 0.2s ease;
        ">OK</button>
      </div>
    `;

    const cancelBtn = dialog.querySelector(".confirm-cancel");
    const okBtn = dialog.querySelector(".confirm-ok");

    cancelBtn.addEventListener("mouseover", () => {
      cancelBtn.style.background = "var(--border)";
    });
    cancelBtn.addEventListener("mouseout", () => {
      cancelBtn.style.background = "var(--panel)";
    });

    okBtn.addEventListener("mouseover", () => {
      okBtn.style.opacity = "0.9";
    });
    okBtn.addEventListener("mouseout", () => {
      okBtn.style.opacity = "1";
    });

    cancelBtn.addEventListener("click", () => {
      backdrop.remove();
      resolve(false);
    });

    okBtn.addEventListener("click", () => {
      backdrop.remove();
      resolve(true);
    });

    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);

    okBtn.focus();
  });
}

// ─── Guard: redirect to login if no token ────────────────────────────────────
(function () {
  if (!sessionStorage.getItem("adminToken")) {
    window.location.href = "index.html";
  }
})();

function token() {
  return sessionStorage.getItem("adminToken") || "";
}

// ─── Page Navigation ──────────────────────────────────────────────────────────
function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const pages = {
    dashboard: document.getElementById("dashboardPage"),
    libraries: document.getElementById("librariesPage"),
  };

  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      const pageName = item.getAttribute("data-page");

      // Hide all pages
      Object.values(pages).forEach((page) => {
        if (page) page.classList.add("hidden");
      });

      // Show selected page
      if (pages[pageName]) {
        pages[pageName].classList.remove("hidden");
      }

      // Update nav active state
      navItems.forEach((i) => i.classList.remove("active"));
      item.classList.add("active");

      // Load page-specific data
      if (pageName === "libraries") {
        loadLibsList();
      } else if (pageName === "dashboard") {
        loadStats();
      }
    });
  });
}

// ─── Logout ───────────────────────────────────────────────────────────────────
document.getElementById("logoutBtn").addEventListener("click", () => {
  sessionStorage.removeItem("adminToken");
  window.location.href = "index.html";
});

// ─── Utilities ────────────────────────────────────────────────────────────────
function showResult(el, msg, type = "error") {
  el.textContent = msg;
  el.className = "result " + type;
}
function hideResult(el) {
  el.className = "result hidden";
}
function setLoading(btn, on) {
  const t = btn.querySelector(".btn-text");
  const l = btn.querySelector(".btn-loader");
  if (t) t.style.display = on ? "none" : "";
  if (l) l.style.display = on ? "flex" : "none";
  btn.disabled = on;
}

async function apiFetch(action, extra = {}) {
  const fd = new FormData();
  fd.append("action", action);
  fd.append("token", token());
  for (const [k, v] of Object.entries(extra)) fd.append(k, v);
  const r = await fetch(API, { method: "POST", body: fd });
  return r.json();
}

// ─── Generate Keys ────────────────────────────────────────────────────────────
const generateBtn = document.getElementById("generateBtn");
const genResult = document.getElementById("genResult");
const genKeys = document.getElementById("genKeys");
const keysList = document.getElementById("keysList");

generateBtn.addEventListener("click", async () => {
  hideResult(genResult);
  setLoading(generateBtn, true);
  genKeys.classList.add("hidden");

  const customNameValue = document.getElementById("keyCustomName").value.trim();
  console.log("Custom name value:", customNameValue);

  try {
    const data = await apiFetch("generate_keys", {
      duration: document.getElementById("keyDuration").value,
      qty: document.getElementById("keyQty").value || 1,
      custom_name: customNameValue,
      max_devices: document.getElementById("keyMaxDevices").value || 0,
    });
    console.log("API Response:", data);

    if (data.success) {
      showResult(
        genResult,
        `✓ Generated ${data.keys.length} key(s)`,
        "success",
      );
      keysList.innerHTML = data.keys
        .map(
          (k) => `
        <div class="gen-key-item">
          <span>${k}</span>
          <button onclick="copyText('${k}', this)">COPY</button>
        </div>
      `,
        )
        .join("");
      genKeys.classList.remove("hidden");
      loadStats();
    } else {
      showResult(genResult, "✗ " + (data.message || "Failed"), "error");
    }
  } catch (e) {
    showResult(genResult, "Error: " + e.message, "error");
  } finally {
    setLoading(generateBtn, false);
  }
});

document.getElementById("copyAllBtn").addEventListener("click", () => {
  const keys = [...document.querySelectorAll(".gen-key-item span")].map(
    (e) => e.textContent,
  );
  navigator.clipboard.writeText(keys.join("\n")).then(() => {
    const btn = document.getElementById("copyAllBtn");
    btn.textContent = "COPIED!";
    setTimeout(() => (btn.textContent = "COPY ALL"), 1500);
  });
});

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "✓";
    setTimeout(() => (btn.textContent = orig), 1200);
  });
}

// ─── Stats ────────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await apiFetch("get_stats");
    if (data.success) {
      document.getElementById("statTotal").textContent = data.total ?? "—";
      document.getElementById("statActive").textContent = data.active ?? "—";
      document.getElementById("statUnused").textContent = data.unused ?? "—";
      document.getElementById("statExpired").textContent = data.expired ?? "—";
    }
  } catch {}
}
document.getElementById("refreshStatsBtn").addEventListener("click", loadStats);

// ─── Key Table ────────────────────────────────────────────────────────────────
document.getElementById("loadKeysBtn").addEventListener("click", loadKeysList);
document
  .getElementById("searchKey")
  .addEventListener("input", debounce(loadKeysList, 350));
document
  .getElementById("filterStatus")
  .addEventListener("change", loadKeysList);

async function loadKeysList() {
  const keysBody = document.getElementById("keysBody");
  keysBody.innerHTML =
    '<tr><td colspan="8" class="empty-msg">Loading...</td></tr>';
  try {
    const data = await apiFetch("list_keys", {
      search: document.getElementById("searchKey").value,
      status: document.getElementById("filterStatus").value,
    });

    if (!data.success) {
      keysBody.innerHTML = `<tr><td colspan="8" class="empty-msg">${data.message}</td></tr>`;
      return;
    }
    if (!data.keys?.length) {
      keysBody.innerHTML =
        '<tr><td colspan="8" class="empty-msg">No keys found.</td></tr>';
      return;
    }

    keysBody.innerHTML = data.keys
      .map(
        (k) => `
      <tr class="key-row" data-key="${k.key}">
        <td><input type="checkbox" class="key-checkbox" value="${k.key}" /></td>
        <td style="font-family:var(--font-mono);color:var(--accent)">${k.key}</td>
        <td><span class="badge ${k.status}">${k.status.toUpperCase()}</span></td>
        <td>${k.expires || "Lifetime"}</td>
        <td>${k.device_count || 0}/${k.max_devices || "Unlimited"}</td>
        <td title="${k.hwid || ""}">${k.hwid ? k.hwid.slice(0, 12) + "…" : "—"}</td>
        <td>
          <button class="action-btn copy-key" onclick="copyText('${k.key}',this)">COPY</button>
          <button class="action-btn" onclick="deleteKey('${k.key}')">DELETE</button>
          ${k.device_count && k.device_count > 0 ? `<button class="action-btn" onclick="resetDeviceCount('${k.key}')">RESET DEVICES</button>` : ""}
          ${k.hwid ? `<button class="action-btn" onclick="resetHWID('${k.key}')">RESET</button>` : ""}
        </td>
      </tr>
    `,
      )
      .join("");

    attachCheckboxListeners();
  } catch (e) {
    keysBody.innerHTML = `<tr><td colspan="8" class="empty-msg">Error: ${e.message}</td></tr>`;
  }
}

function attachCheckboxListeners() {
  const selectAllCheckbox = document.getElementById("selectAllKeys");
  const keyCheckboxes = document.querySelectorAll(".key-checkbox");
  const deleteSelectedBtn = document.getElementById("deleteSelectedBtn");

  selectAllCheckbox.addEventListener("change", () => {
    keyCheckboxes.forEach((cb) => (cb.checked = selectAllCheckbox.checked));
    updateDeleteButtonVisibility();
  });

  keyCheckboxes.forEach((cb) => {
    cb.addEventListener("change", () => {
      selectAllCheckbox.checked = Array.from(keyCheckboxes).every(
        (checkbox) => checkbox.checked,
      );
      updateDeleteButtonVisibility();
    });
  });

  deleteSelectedBtn.addEventListener("click", deleteBatchKeys);
}

function updateDeleteButtonVisibility() {
  const keyCheckboxes = document.querySelectorAll(".key-checkbox:checked");
  const deleteSelectedBtn = document.getElementById("deleteSelectedBtn");
  deleteSelectedBtn.style.display = keyCheckboxes.length > 0 ? "block" : "none";
}

async function deleteBatchKeys() {
  const selectedCheckboxes = document.querySelectorAll(".key-checkbox:checked");
  if (selectedCheckboxes.length === 0) return;

  const keys = Array.from(selectedCheckboxes).map((cb) => cb.value);
  const plural = keys.length === 1 ? "key" : "keys";
  const confirmed = await showConfirmDialog(
    `Permanently delete ${keys.length} ${plural}?\n\nThis action cannot be undone.`,
    "Confirm Deletion",
  );
  if (!confirmed) return;

  const deleteBtn = document.getElementById("deleteSelectedBtn");
  setLoading(deleteBtn, true);

  try {
    for (const key of keys) {
      await apiFetch("delete_key", { key });
    }
    loadKeysList();
    loadStats();
  } catch (e) {
    alert("Error deleting keys: " + e.message);
  } finally {
    setLoading(deleteBtn, false);
  }
}

async function deleteKey(key) {
  const confirmed = await showConfirmDialog(
    `Permanently delete this key?\n\n${key}\n\nThis action cannot be undone.`,
    "Confirm Deletion",
  );
  if (!confirmed) return;
  await apiFetch("delete_key", { key });
  loadKeysList();
  loadStats();
}

async function resetHWID(key) {
  if (
    !confirm(
      `Reset HWID for: ${key}?\nThis allows the key to be used on a new device.`,
    )
  )
    return;
  await apiFetch("reset_hwid", { key });
  loadKeysList();
}

async function resetDeviceCount(key) {
  const confirmed = await showConfirmDialog(
    `Reset device count and HWID for: ${key}?\n\nThis will clear all device registrations (${deviceCount} devices) and the key can be used on new devices.`,
    "Confirm Device Reset",
  );
  if (!confirmed) return;

  try {
    // FIX: Use the reset_device_count endpoint which should clear both
    const data = await apiFetch("reset_device_count", { key });
    if (data.success) {
      showResult(
        document.getElementById("genResult"),
        "✓ Device count and HWIDs reset successfully",
        "success",
      );
      loadKeysList();
    } else {
      showResult(
        document.getElementById("genResult"),
        "✗ " + (data.message || "Failed to reset"),
        "error",
      );
    }
  } catch (e) {
    showResult(
      document.getElementById("genResult"),
      "Error: " + e.message,
      "error",
    );
  }
}
// ─── Library Management ────────────────────────────────────────────────────────

const fileUploadArea = document.getElementById("fileUploadArea");
const libFileInput = document.getElementById("libFileInput");
const uploadBtn = document.getElementById("uploadBtn");
const uploadResult = document.getElementById("uploadResult");
const uploadProgress = document.getElementById("uploadProgress");
let selectedFile = null;

// Drag and drop
fileUploadArea.addEventListener("click", () => libFileInput.click());
fileUploadArea.addEventListener("dragover", (e) => {
  e.preventDefault();
  fileUploadArea.style.borderColor = "var(--accent)";
  fileUploadArea.style.background = "rgba(0, 245, 255, 0.05)";
});
fileUploadArea.addEventListener("dragleave", () => {
  fileUploadArea.style.borderColor = "var(--border)";
  fileUploadArea.style.background = "transparent";
});
fileUploadArea.addEventListener("drop", (e) => {
  e.preventDefault();
  fileUploadArea.style.borderColor = "var(--border)";
  fileUploadArea.style.background = "transparent";
  if (e.dataTransfer.files.length > 0) {
    handleFileSelect(e.dataTransfer.files[0]);
  }
});

libFileInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    handleFileSelect(e.target.files[0]);
  }
});

function handleFileSelect(file) {
  if (!file.name.endsWith(".so")) {
    showResult(uploadResult, "✗ Only .SO files are allowed", "error");
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    showResult(
      uploadResult,
      `✗ File exceeds 20 MB limit (${(file.size / 1024 / 1024).toFixed(2)} MB)`,
      "error",
    );
    return;
  }
  selectedFile = file;
  document.getElementById("libName").value = file.name;
  showResult(
    uploadResult,
    `✓ File selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`,
    "success",
  );
}

uploadBtn.addEventListener("click", async () => {
  if (!selectedFile) {
    showResult(uploadResult, "Please select a .SO file", "warn");
    return;
  }

  const libName = document.getElementById("libName").value.trim();
  const libVersion = document.getElementById("libVersion").value.trim();
  const libDescription = document.getElementById("libDescription").value.trim();

  if (!libName) {
    showResult(uploadResult, "Library name is required", "warn");
    return;
  }

  hideResult(uploadResult);
  setLoading(uploadBtn, true);
  uploadProgress.classList.remove("hidden");

  try {
    const fd = new FormData();
    fd.append("action", "upload_library");
    fd.append("token", token());
    fd.append("library_file", selectedFile);
    fd.append("lib_name", libName);
    fd.append("lib_version", libVersion);
    fd.append("lib_description", libDescription);

    const xhr = new XMLHttpRequest();

    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        const percentComplete = (e.loaded / e.total) * 100;
        document.getElementById("progressFill").style.width =
          percentComplete + "%";
        document.getElementById("progressText").textContent =
          `Uploading... ${Math.round(percentComplete)}%`;
      }
    });

    xhr.addEventListener("load", () => {
      uploadProgress.classList.add("hidden");
      if (xhr.status === 200) {
        const data = JSON.parse(xhr.responseText);
        if (data.success) {
          showResult(
            uploadResult,
            `✓ Library uploaded successfully`,
            "success",
          );
          selectedFile = null;
          libFileInput.value = "";
          document.getElementById("libName").value = "";
          document.getElementById("libVersion").value = "";
          document.getElementById("libDescription").value = "";
          setTimeout(() => loadLibsList(), 1000);
        } else {
          showResult(
            uploadResult,
            "✗ " + (data.message || "Upload failed"),
            "error",
          );
        }
      } else {
        showResult(uploadResult, "✗ Server error: " + xhr.status, "error");
      }
      setLoading(uploadBtn, false);
    });

    xhr.addEventListener("error", () => {
      uploadProgress.classList.add("hidden");
      showResult(uploadResult, "✗ Network error during upload", "error");
      setLoading(uploadBtn, false);
    });

    xhr.open("POST", API);
    xhr.send(fd);
  } catch (e) {
    uploadProgress.classList.add("hidden");
    showResult(uploadResult, "Error: " + e.message, "error");
    setLoading(uploadBtn, false);
  }
});

// Library List
document.getElementById("loadLibsBtn").addEventListener("click", loadLibsList);
document
  .getElementById("searchLib")
  .addEventListener("input", debounce(loadLibsList, 350));

async function loadLibsList() {
  const libsBody = document.getElementById("libsBody");
  libsBody.innerHTML =
    '<tr><td colspan="7" class="empty-msg">Loading...</td></tr>';

  try {
    const data = await apiFetch("list_libraries", {
      search: document.getElementById("searchLib").value,
    });

    if (!data.success) {
      libsBody.innerHTML = `<tr><td colspan="7" class="empty-msg">${data.message}</td></tr>`;
      return;
    }
    if (!data.libraries?.length) {
      libsBody.innerHTML =
        '<tr><td colspan="7" class="empty-msg">No libraries found.</td></tr>';
      return;
    }

    libsBody.innerHTML = data.libraries
      .map(
        (lib) => `
      <tr class="lib-row" data-file="${lib.filename}">
        <td><input type="checkbox" class="lib-checkbox" value="${lib.filename}" /></td>
        <td style="font-family:var(--font-mono);color:var(--accent)">${lib.filename}</td>
        <td>${formatFileSize(lib.size)}</td>
        <td>${lib.version || "—"}</td>
        <td>${lib.uploaded || "—"}</td>
        <td>${lib.description || "—"}</td>
        <td>
          <button class="action-btn" onclick="downloadLibrary('${lib.filename}')">DOWNLOAD</button>
          <button class="action-btn" onclick="deleteLibrary('${lib.filename}')">DELETE</button>
        </td>
      </tr>
    `,
      )
      .join("");

    attachLibCheckboxListeners();
  } catch (e) {
    libsBody.innerHTML = `<tr><td colspan="7" class="empty-msg">Error: ${e.message}</td></tr>`;
  }
}

function attachLibCheckboxListeners() {
  const selectAllCheckbox = document.getElementById("selectAllLibs");
  const libCheckboxes = document.querySelectorAll(".lib-checkbox");
  const deleteSelectedBtn = document.getElementById("deleteSelectedLibBtn");

  selectAllCheckbox.addEventListener("change", () => {
    libCheckboxes.forEach((cb) => (cb.checked = selectAllCheckbox.checked));
    updateDeleteLibButtonVisibility();
  });

  libCheckboxes.forEach((cb) => {
    cb.addEventListener("change", () => {
      selectAllCheckbox.checked = Array.from(libCheckboxes).every(
        (checkbox) => checkbox.checked,
      );
      updateDeleteLibButtonVisibility();
    });
  });

  deleteSelectedBtn.addEventListener("click", deleteBatchLibraries);
}

function updateDeleteLibButtonVisibility() {
  const libCheckboxes = document.querySelectorAll(".lib-checkbox:checked");
  const deleteSelectedBtn = document.getElementById("deleteSelectedLibBtn");
  deleteSelectedBtn.style.display = libCheckboxes.length > 0 ? "block" : "none";
}

async function deleteBatchLibraries() {
  const selectedCheckboxes = document.querySelectorAll(".lib-checkbox:checked");
  if (selectedCheckboxes.length === 0) return;

  const files = Array.from(selectedCheckboxes).map((cb) => cb.value);
  const plural = files.length === 1 ? "library" : "libraries";
  const confirmed = await showConfirmDialog(
    `Permanently delete ${files.length} ${plural}?\n\nThis action cannot be undone.`,
    "Confirm Deletion",
  );
  if (!confirmed) return;

  const deleteBtn = document.getElementById("deleteSelectedLibBtn");
  setLoading(deleteBtn, true);

  try {
    for (const file of files) {
      await apiFetch("delete_library", { filename: file });
    }
    loadLibsList();
  } catch (e) {
    alert("Error deleting libraries: " + e.message);
  } finally {
    setLoading(deleteBtn, false);
  }
}

async function deleteLibrary(filename) {
  const confirmed = await showConfirmDialog(
    `Permanently delete this library?\n\n${filename}\n\nThis action cannot be undone.`,
    "Confirm Deletion",
  );
  if (!confirmed) return;
  await apiFetch("delete_library", { filename });
  loadLibsList();
}

async function downloadLibrary(filename) {
  const link = document.createElement("a");
  link.href = `./api.php?action=download_library&filename=${encodeURIComponent(filename)}&token=${encodeURIComponent(token())}`;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function debounce(fn, ms) {
  let t;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}

// ─── Init ─────────────────────────────────────────────────────────────────────
initNavigation();
loadStats();
