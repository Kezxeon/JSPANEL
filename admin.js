const API = "./api.php";
const MAX_FILE_SIZE = 20 * 1024 * 1024;

function showConfirmDialog(message, title = "Confirm Action") {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "confirm-dialog";

    const dialog = document.createElement("div");
    dialog.className = "confirm-dialog-content";

    dialog.innerHTML = `
      <div class="confirm-dialog-header">
        <span>⚠️</span>
        <span>${title}</span>
      </div>
      <div class="confirm-dialog-message">${message}</div>
      <div class="confirm-dialog-buttons">
        <button class="confirm-cancel">CANCEL</button>
        <button class="confirm-ok">OK</button>
      </div>
    `;

    const cancelBtn = dialog.querySelector(".confirm-cancel");
    const okBtn = dialog.querySelector(".confirm-ok");

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

(function () {
  if (!sessionStorage.getItem("adminToken")) {
    window.location.href = "index.html";
  }
})();

function token() {
  return sessionStorage.getItem("adminToken") || "";
}

function initNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const pages = {
    dashboard: document.getElementById("dashboardPage"),
    libraries: document.getElementById("librariesPage"),
  };

  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      const pageName = item.getAttribute("data-page");

      Object.values(pages).forEach((page) => {
        if (page) page.classList.add("hidden");
      });

      if (pages[pageName]) {
        pages[pageName].classList.remove("hidden");
      }

      navItems.forEach((i) => i.classList.remove("active"));
      item.classList.add("active");

      if (pageName === "libraries") {
        loadLibsList();
      } else if (pageName === "dashboard") {
        loadStats();
      }
    });
  });
}

document.getElementById("logoutBtn").addEventListener("click", () => {
  sessionStorage.removeItem("adminToken");
  window.location.href = "index.html";
});

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

const generateBtn = document.getElementById("generateBtn");
const genResult = document.getElementById("genResult");
const genKeys = document.getElementById("genKeys");
const keysList = document.getElementById("keysList");

generateBtn.addEventListener("click", async () => {
  hideResult(genResult);
  setLoading(generateBtn, true);
  genKeys.classList.add("hidden");

  const customNameValue = document.getElementById("keyCustomName").value.trim();

  try {
    const data = await apiFetch("generate_keys", {
      duration: document.getElementById("keyDuration").value,
      qty: document.getElementById("keyQty").value || 1,
      custom_name: customNameValue,
      max_devices: document.getElementById("keyMaxDevices").value || 1,
    });

    if (data.success) {
      showResult(
        genResult,
        `✓ Generated ${data.keys.length} key(s)`,
        "success",
      );

      const template = document.getElementById("gen-key-item-template");
      keysList.innerHTML = "";

      data.keys.forEach((key) => {
        const clone = template.content.cloneNode(true);
        clone.querySelector("span").textContent = key;
        const copyBtn = clone.querySelector(".copy-gen-key");
        copyBtn.addEventListener("click", () => copyText(key, copyBtn));
        keysList.appendChild(clone);
      });

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

    const template = document.getElementById("key-row-template");
    keysBody.innerHTML = "";

    data.keys.forEach((k) => {
      const clone = template.content.cloneNode(true);
      const row = clone.querySelector("tr");
      row.setAttribute("data-key", k.key);

      const checkbox = row.querySelector(".key-checkbox");
      checkbox.value = k.key;

      row.querySelector("td:nth-child(2)").textContent = k.key;

      const badge = row.querySelector(".badge");
      badge.className = `badge ${k.status}`;
      badge.textContent = k.status.toUpperCase();

      row.querySelector("td:nth-child(4)").textContent =
        k.expires || "Lifetime";

      row.querySelector("td:nth-child(5)").textContent =
        `${k.device_count || 0}/${k.max_devices}`;

      const copyBtn = row.querySelector(".copy-key");
      copyBtn.addEventListener("click", () => copyText(k.key, copyBtn));

      const deleteBtn = row.querySelector(".delete-key");
      deleteBtn.addEventListener("click", () => deleteKey(k.key));

      const resetBtn = row.querySelector(".reset-device");
      resetBtn.textContent =
        k.device_count && k.device_count > 0
          ? `RESET (${k.device_count})`
          : "RESET";
      resetBtn.addEventListener("click", () => resetDeviceCount(k.key));

      keysBody.appendChild(clone);
    });

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

async function resetDeviceCount(key) {
  const keyRow = document.querySelector(`.key-row[data-key="${key}"]`);
  let currentDeviceCount = 0;

  if (keyRow) {
    const devicesCell = keyRow.querySelector("td:nth-child(5)");
    if (devicesCell) {
      const deviceText = devicesCell.textContent;
      const match = deviceText.match(/(\d+)\//);
      if (match) {
        currentDeviceCount = parseInt(match[1]);
      }
    }
  }

  const confirmed = await showConfirmDialog(
    `Reset device count and HWID for: ${key}?\n\nThis will clear all device registrations (${currentDeviceCount} devices) and the key can be used on new devices.`,
    "Confirm Device Reset",
  );
  if (!confirmed) return;

  try {
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

const fileUploadArea = document.getElementById("fileUploadArea");
const libFileInput = document.getElementById("libFileInput");
const uploadBtn = document.getElementById("uploadBtn");
const uploadResult = document.getElementById("uploadResult");
const uploadProgress = document.getElementById("uploadProgress");
let selectedFile = null;

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

    const template = document.getElementById("lib-row-template");
    libsBody.innerHTML = "";

    data.libraries.forEach((lib) => {
      const clone = template.content.cloneNode(true);
      const row = clone.querySelector("tr");
      row.setAttribute("data-file", lib.filename);

      const checkbox = row.querySelector(".lib-checkbox");
      checkbox.value = lib.filename;

      row.querySelector("td:nth-child(2)").textContent = lib.filename;

      row.querySelector("td:nth-child(3)").textContent = formatFileSize(
        lib.size,
      );

      row.querySelector("td:nth-child(4)").textContent = lib.version || "—";

      row.querySelector("td:nth-child(5)").textContent = lib.uploaded || "—";

      row.querySelector("td:nth-child(6)").textContent = lib.description || "—";

      const downloadBtn = row.querySelector(".download-lib");
      downloadBtn.addEventListener("click", () =>
        downloadLibrary(lib.filename),
      );

      const deleteBtn = row.querySelector(".delete-lib");
      deleteBtn.addEventListener("click", () => deleteLibrary(lib.filename));

      libsBody.appendChild(clone);
    });

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

initNavigation();
loadStats();
