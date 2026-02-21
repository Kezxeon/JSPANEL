// admin.js — CFL Admin Panel

const API = './api.php';

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

  try {
    const data = await apiFetch('generate_keys', {
      duration: document.getElementById('keyDuration').value,
      qty:      document.getElementById('keyQty').value || 1,
      note:     document.getElementById('keyNote').value,
    });

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
  keysBody.innerHTML = '<tr><td colspan="6" class="empty-msg">Loading...</td></tr>';
  try {
    const data = await apiFetch('list_keys', {
      search: document.getElementById('searchKey').value,
      status: document.getElementById('filterStatus').value,
    });

    if (!data.success) { keysBody.innerHTML = `<tr><td colspan="6" class="empty-msg">${data.message}</td></tr>`; return; }
    if (!data.keys?.length) { keysBody.innerHTML = '<tr><td colspan="6" class="empty-msg">No keys found.</td></tr>'; return; }

    keysBody.innerHTML = data.keys.map(k => `
      <tr>
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
  } catch(e) {
    keysBody.innerHTML = `<tr><td colspan="6" class="empty-msg">Error: ${e.message}</td></tr>`;
  }
}

async function deleteKey(key) {
  if (!confirm(`Delete key: ${key}?`)) return;
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