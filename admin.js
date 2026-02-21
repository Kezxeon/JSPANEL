// admin.js — CFL Admin Panel
 
const API = './api.php';

// ─── Custom Confirmation Dialog ────────────────────────────────────────────
function showConfirmDialog(message, title = "Confirm Action") {
  return new Promise((resolve) => {
    const backdrop = document.createElement('div');
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

    const dialog = document.createElement('div');
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

    const cancelBtn = dialog.querySelector('.confirm-cancel');
    const okBtn = dialog.querySelector('.confirm-ok');

    cancelBtn.addEventListener('mouseover', () => {
      cancelBtn.style.background = 'var(--border)';
    });
    cancelBtn.addEventListener('mouseout', () => {
      cancelBtn.style.background = 'var(--panel)';
    });

    okBtn.addEventListener('mouseover', () => {
      okBtn.style.opacity = '0.9';
    });
    okBtn.addEventListener('mouseout', () => {
      okBtn.style.opacity = '1';
    });

    cancelBtn.addEventListener('click', () => {
      backdrop.remove();
      resolve(false);
    });

    okBtn.addEventListener('click', () => {
      backdrop.remove();
      resolve(true);
    });

    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);

    okBtn.focus();
  });
}

// ─── Guard: redirect to login if no token ────────────────────────────────────
(function() {
  if (!sessionStorage.getItem('adminToken')) {
    window.location.href = 'index.html';
  }
})();

function token() { return sessionStorage.getItem('adminToken') || ''; }

// ─── Logout ───────────────────────────────────────────────────────────────────
document.getElementById('logoutBtn').addEventListener('click', () => {
  sessionStorage.removeItem('adminToken');
  window.location.href = 'index.html';
});

// ─── Utilities ────────────────────────────────────────────────────────────────
function showResult(el, msg, type = 'error') {
  el.textContent = msg;
  el.className = 'result ' + type;
}
function hideResult(el) { el.className = 'result hidden'; }
function setLoading(btn, on) {
  const t = btn.querySelector('.btn-text');
  const l = btn.querySelector('.btn-loader');
  if (t) t.style.display = on ? 'none' : '';
  if (l) l.style.display = on ? 'flex' : 'none';
  btn.disabled = on;
}

async function apiFetch(action, extra = {}) {
  const fd = new FormData();
  fd.append('action', action);
  fd.append('token', token());
  for (const [k, v] of Object.entries(extra)) fd.append(k, v);
  const r = await fetch(API, { method: 'POST', body: fd });
  return r.json();
}

// ─── Generate Keys ────────────────────────────────────────────────────────────
const generateBtn = document.getElementById('generateBtn');
const genResult   = document.getElementById('genResult');
const genKeys     = document.getElementById('genKeys');
const keysList    = document.getElementById('keysList');

generateBtn.addEventListener('click', async () => {
  hideResult(genResult);
  setLoading(generateBtn, true);
  genKeys.classList.add('hidden');

  const customNameValue = document.getElementById('keyCustomName').value.trim();
  console.log('Custom name value:', customNameValue);

  try {
    const data = await apiFetch('generate_keys', {
      duration: document.getElementById('keyDuration').value,
      qty:      document.getElementById('keyQty').value || 1,
      custom_name: customNameValue,
      note:     document.getElementById('keyNote').value,
    });
    console.log('API Response:', data);

    if (data.success) {
      showResult(genResult, `✓ Generated ${data.keys.length} key(s)`, 'success');
      keysList.innerHTML = data.keys.map(k => `
        <div class="gen-key-item">
          <span>${k}</span>
          <button onclick="copyText('${k}', this)">COPY</button>
        </div>
      `).join('');
      genKeys.classList.remove('hidden');
      loadStats();
    } else {
      showResult(genResult, '✗ ' + (data.message || 'Failed'), 'error');
    }
  } catch(e) {
    showResult(genResult, 'Error: ' + e.message, 'error');
  } finally {
    setLoading(generateBtn, false);
  }
});

document.getElementById('copyAllBtn').addEventListener('click', () => {
  const keys = [...document.querySelectorAll('.gen-key-item span')].map(e => e.textContent);
  navigator.clipboard.writeText(keys.join('\n')).then(() => {
    const btn = document.getElementById('copyAllBtn');
    btn.textContent = 'COPIED!';
    setTimeout(() => btn.textContent = 'COPY ALL', 1500);
  });
});

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = orig, 1200);
  });
}

// ─── Stats ────────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await apiFetch('get_stats');
    if (data.success) {
      document.getElementById('statTotal').textContent   = data.total   ?? '—';
      document.getElementById('statActive').textContent  = data.active  ?? '—';
      document.getElementById('statUnused').textContent  = data.unused  ?? '—';
      document.getElementById('statExpired').textContent = data.expired ?? '—';
    }
  } catch {}
}
document.getElementById('refreshStatsBtn').addEventListener('click', loadStats);

// ─── Key Table ────────────────────────────────────────────────────────────────
document.getElementById('loadKeysBtn').addEventListener('click', loadKeysList);
document.getElementById('searchKey').addEventListener('input', debounce(loadKeysList, 350));
document.getElementById('filterStatus').addEventListener('change', loadKeysList);

async function loadKeysList() {
  const keysBody = document.getElementById('keysBody');
  keysBody.innerHTML = '<tr><td colspan="7" class="empty-msg">Loading...</td></tr>';
  try {
    const data = await apiFetch('list_keys', {
      search: document.getElementById('searchKey').value,
      status: document.getElementById('filterStatus').value,
    });

    if (!data.success) { keysBody.innerHTML = `<tr><td colspan="7" class="empty-msg">${data.message}</td></tr>`; return; }
    if (!data.keys?.length) { keysBody.innerHTML = '<tr><td colspan="7" class="empty-msg">No keys found.</td></tr>'; return; }

    keysBody.innerHTML = data.keys.map(k => `
      <tr class="key-row" data-key="${k.key}">
        <td><input type="checkbox" class="key-checkbox" value="${k.key}" /></td>
        <td style="font-family:var(--font-mono);color:var(--accent)">${k.key}</td>
        <td><span class="badge ${k.status}">${k.status.toUpperCase()}</span></td>
        <td>${k.expires || 'Lifetime'}</td>
        <td title="${k.hwid||''}">${k.hwid ? k.hwid.slice(0,12)+'…' : '—'}</td>
        <td>${k.note || '—'}</td>
        <td>
          <button class="action-btn copy-key" onclick="copyText('${k.key}',this)">COPY</button>
          <button class="action-btn" onclick="deleteKey('${k.key}')">DELETE</button>
          ${k.hwid ? `<button class="action-btn" onclick="resetHWID('${k.key}')">RESET</button>` : ''}
        </td>
      </tr>
    `).join('');
    
    // Attach checkbox event listeners
    attachCheckboxListeners();
  } catch(e) {
    keysBody.innerHTML = `<tr><td colspan="7" class="empty-msg">Error: ${e.message}</td></tr>`;
  }
}

function attachCheckboxListeners() {
  const selectAllCheckbox = document.getElementById('selectAllKeys');
  const keyCheckboxes = document.querySelectorAll('.key-checkbox');
  const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
  
  selectAllCheckbox.addEventListener('change', () => {
    keyCheckboxes.forEach(cb => cb.checked = selectAllCheckbox.checked);
    updateDeleteButtonVisibility();
  });
  
  keyCheckboxes.forEach(cb => {
    cb.addEventListener('change', () => {
      selectAllCheckbox.checked = Array.from(keyCheckboxes).every(checkbox => checkbox.checked);
      updateDeleteButtonVisibility();
    });
  });
  
  deleteSelectedBtn.addEventListener('click', deleteBatchKeys);
}

function updateDeleteButtonVisibility() {
  const keyCheckboxes = document.querySelectorAll('.key-checkbox:checked');
  const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
  deleteSelectedBtn.style.display = keyCheckboxes.length > 0 ? 'block' : 'none';
}

async function deleteBatchKeys() {
  const selectedCheckboxes = document.querySelectorAll('.key-checkbox:checked');
  if (selectedCheckboxes.length === 0) return;
  
  const keys = Array.from(selectedCheckboxes).map(cb => cb.value);
  const plural = keys.length === 1 ? 'key' : 'keys';
  const confirmed = await showConfirmDialog(`Permanently delete ${keys.length} ${plural}?\n\nThis action cannot be undone.`, 'Confirm Deletion');
  if (!confirmed) return;
  
  const deleteBtn = document.getElementById('deleteSelectedBtn');
  setLoading(deleteBtn, true);
  
  try {
    for (const key of keys) {
      await apiFetch('delete_key', { key });
    }
    loadKeysList();
    loadStats();
  } catch(e) {
    alert('Error deleting keys: ' + e.message);
  } finally {
    setLoading(deleteBtn, false);
  }
}

async function deleteKey(key) {
  const confirmed = await showConfirmDialog(`Permanently delete this key?\n\n${key}\n\nThis action cannot be undone.`, 'Confirm Deletion');
  if (!confirmed) return;
  await apiFetch('delete_key', { key });
  loadKeysList(); loadStats();
}

async function resetHWID(key) {
  if (!confirm(`Reset HWID for: ${key}?\nThis allows the key to be used on a new device.`)) return;
  await apiFetch('reset_hwid', { key });
  loadKeysList();
}

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ─── Init ─────────────────────────────────────────────────────────────────────
loadStats();