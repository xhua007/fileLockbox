'use strict';

// ===== Tauri IPC（不依赖 window.__TAURI__ 全局）=====
const TAURI_INTERNALS = window.__TAURI_INTERNALS__;
const invoke = (cmd, args) => TAURI_INTERNALS.invoke(cmd, args);

async function listen(event, handler) {
  const eventId = await invoke('plugin:event|listen', {
    event,
    target: { kind: 'Any' },
    handler: TAURI_INTERNALS.transformCallback(handler),
  });
  return () => invoke('plugin:event|unlisten', { event, eventId }).catch(() => {});
}

// ===== State =====
const state = {
  screen: 'loading',
  currentVault: null,
  vaults: [],
  entries: [],
  filteredEntries: [],
  selectedIds: new Set(),
  multiSelectMode: false,
  searchQuery: '',
  sortBy: 'time',
  sortAsc: false,
  hasSavedPassword: false,
  autoLockMinutes: 5,
  idleTimer: null,
  lastActivity: Date.now(),
  contextMenuTargetId: null,
  pendingRecoveryCode: '',
  recoveryStep: 1,
  recoveryCodeInput: '',
  modalOpen: false,
  lockoutRemaining: 0,
  lockoutInterval: null,
};

// ===== Utility =====
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
function el(tag, attrs = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'style') e.style.cssText = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else if (k === 'html') e.innerHTML = v;
    else e.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return e;
}

const CHEVRON_DOWN_SVG = '<svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.5 5.25L7 8.75L10.5 5.25" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function getCurrentVaultName(fallback = '默认保险箱') {
  return state.currentVault ? state.currentVault.name : fallback;
}

function createVaultPill(opts = {}) {
  const vaultName = getCurrentVaultName(opts.defaultName || '默认保险箱');
  const attrs = {
    class: 'vault-pill' + (opts.class ? ' ' + opts.class : ''),
    title: opts.title || '切换或管理保险箱',
    onclick: e => toggleVaultMenu(e)
  };
  if (opts.id) attrs.id = opts.id;
  if (opts.style) attrs.style = opts.style;

  return el('div', attrs, [
    el('span', { class: 'vault-shield' + (opts.isMain ? ' topbar-shield' : '') }, '🛡️'),
    el('span', { class: opts.isMain ? 'topbar-title' : 'vault-name' }, vaultName),
    el('span', { class: 'arrow', html: CHEVRON_DOWN_SVG })
  ]);
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024*1024)).toFixed(1) + ' MB';
  return (bytes / (1024*1024*1024)).toFixed(2) + ' GB';
}

function formatDate(ts) {
  const d = new Date(ts);
  try {
    return new Intl.DateTimeFormat('zh-CN', { year:'numeric', month:'long', day:'numeric', hour:'numeric', minute:'2-digit', hour12: true }).format(d);
  } catch {
    return d.toLocaleString('zh-CN');
  }
}

function getCategory(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (['jpg','jpeg','png','gif','bmp','webp','svg','heic','tiff','ico'].includes(ext)) return '图片';
  if (['mp4','mov','avi','mkv','flv','wmv','webm','m4v'].includes(ext)) return '视频';
  if (['mp3','wav','flac','aac','ogg','m4a','wma'].includes(ext)) return '音频';
  if (['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','rtf','md','pages','numbers','key'].includes(ext)) return '文档';
  if (['zip','rar','7z','tar','gz','bz2'].includes(ext)) return '压缩包';
  if (['js','ts','jsx','tsx','py','java','c','cpp','h','rs','go','swift','html','css','json','xml','yml','yaml'].includes(ext)) return '代码';
  return '其他';
}

function showToast(msg, isError = false) {
  const container = $('#toastContainer');
  const t = el('div', { class: 'toast' + (isError ? ' error' : '') }, msg);
  container.appendChild(t);
  setTimeout(() => {
    t.style.transition = 'opacity 0.3s, transform 0.3s';
    t.style.opacity = '0';
    t.style.transform = 'translateY(-10px)';
    setTimeout(() => t.remove(), 300);
  }, 2500);
}
function showError(msg) { showToast(msg, true); }

// ===== 密码强度检测 =====
function checkPasswordStrength(pwd) {
  if (!pwd) return { score: 0, text: '', level: 'none', valid: false };
  if (pwd.length < 8) return { score: 1, text: '密码过短（至少 8 位）', level: 'weak', valid: false };

  // 常见弱密码与规律校验
  const weakPatterns = [
    /^12345678/i,
    /^password/i,
    /^qwerty/i,
    /^admin/i,
    /^(\w)\1{7,}$/i, // 全部连续相同字符
    /^\d+$/ // 纯数字
  ];
  for (const pat of weakPatterns) {
    if (pat.test(pwd)) {
      return { score: 1, text: '密码过于简单，容易被 AI/字典工具破解', level: 'weak', valid: false };
    }
  }

  let score = 0;
  if (pwd.length >= 8) score += 1;
  if (pwd.length >= 12) score += 1;
  if (/[a-z]/.test(pwd)) score += 1;
  if (/[A-Z]/.test(pwd)) score += 1;
  if (/[0-9]/.test(pwd)) score += 1;
  if (/[^a-zA-Z0-9]/.test(pwd)) score += 1;

  if (score <= 3) return { score: 2, text: '密码强度：中等（建议混入大写字母与符号）', level: 'medium', valid: true };
  return { score: 3, text: '密码强度：高（具备强抗 AI/暴力破解能力）', level: 'strong', valid: true };
}

function createPasswordInputWithMeter(placeholder) {
  const input = el('input', { type: 'password', class: 'form-input', placeholder, style: 'margin-bottom:6px;' });
  const bar = el('div', { class: 'strength-bar' });
  const meter = el('div', { class: 'strength-meter' }, [bar]);
  const text = el('div', { class: 'strength-text' });

  input.addEventListener('input', () => {
    const res = checkPasswordStrength(input.value);
    if (!input.value) {
      bar.style.width = '0%';
      text.textContent = '';
      return;
    }
    if (res.level === 'weak') {
      bar.style.width = '33%';
      bar.style.background = 'var(--danger)';
      text.textContent = res.text;
      text.style.color = 'var(--danger)';
    } else if (res.level === 'medium') {
      bar.style.width = '66%';
      bar.style.background = '#FF9500';
      text.textContent = res.text;
      text.style.color = '#FF9500';
    } else if (res.level === 'strong') {
      bar.style.width = '100%';
      bar.style.background = '#34C759';
      text.textContent = res.text;
      text.style.color = '#34C759';
    }
  });

  return { input, elements: [input, meter, text] };
}

// ===== Multi-Vault Info =====
async function loadVaultsInfo() {
  try {
    state.vaults = await invoke('list_vaults');
    state.currentVault = await invoke('get_current_vault');
    state.hasSavedPassword = state.currentVault ? state.currentVault.has_saved_password : false;
  } catch (e) {
    console.error('加载保险箱信息失败:', e);
  }
}

async function switchVault(vaultId) {
  hideAllMenus();
  if (state.currentVault && state.currentVault.id === vaultId) return;
  try {
    const info = await invoke('switch_vault', { vaultId });
    state.currentVault = info;
    state.entries = [];
    state.selectedIds.clear();
    state.multiSelectMode = false;
    state.hasSavedPassword = info.has_saved_password;
    if (state.lockoutInterval) { clearInterval(state.lockoutInterval); state.lockoutInterval = null; }
    state.lockoutRemaining = 0;
    await loadVaultsInfo();

    if (info.exists) {
      if (info.has_saved_password) {
        try {
          const entries = await invoke('unlock_with_keychain');
          state.entries = entries;
          if (state.currentVault) state.currentVault.is_unlocked = true;
          showToast(`已切换至「${info.name}」并自动解锁`);
          enterMain();
          return;
        } catch {}
      }
      state.screen = 'unlock';
    } else {
      state.screen = 'setup';
    }
    showToast(`已切换至「${info.name}」`);
    render();
  } catch (e) {
    showError('切换失败: ' + e);
  }
}

// ===== Idle Auto-Lock =====
// Rust 侧为权威判定，前端活动需节流上报心跳（mousemove 频率很高）
let lastActivitySync = 0;
function resetIdleTimer() {
  state.lastActivity = Date.now();
  const now = Date.now();
  if (now - lastActivitySync > 10000) {
    lastActivitySync = now;
    invoke('touch_activity').catch(() => {});
  }
}
async function initAutoLockListener() {
  try {
    await listen('vault-auto-locked', () => {
      if (state.screen !== 'main') return;
      state.entries = [];
      state.selectedIds.clear();
      state.multiSelectMode = false;
      state.searchQuery = '';
      if (state.currentVault) state.currentVault.is_unlocked = false;
      state.screen = 'unlock';
      render();
      showToast('长时间无操作，已自动锁定');
    });
  } catch {}
}
function startIdleMonitor() {
  if (state.idleTimer) clearInterval(state.idleTimer);
  state.idleTimer = setInterval(() => {
    if (state.screen !== 'main') return;
    const mins = state.autoLockMinutes;
    if (mins <= 0) return;
    if (Date.now() - state.lastActivity >= mins * 60 * 1000) doLock();
  }, 5000);
}
['mousemove','keydown','click','scroll','touchstart'].forEach(evt => {
  window.addEventListener(evt, resetIdleTimer, true);
});

// ===== Rendering =====
function render() {
  const app = $('#app');
  app.innerHTML = '';
  hideAllMenus();
  switch (state.screen) {
    case 'loading': app.appendChild(renderLoading()); break;
    case 'setup': app.appendChild(renderSetup()); break;
    case 'unlock': app.appendChild(renderUnlock()); break;
    case 'main': app.appendChild(renderMain()); setupDragDrop(); break;
    case 'recovery-code': app.appendChild(renderRecoveryCode()); break;
    case 'recovery-flow': app.appendChild(renderRecoveryFlow()); break;
  }
}

function renderLoading() {
  return el('div', { class: 'auth-container' },
    el('div', { class: 'auth-card' }, [
      el('div', { class: 'lock-icon' }, '🔒'),
      el('div', { class: 'auth-title' }, '文件保险箱'),
      el('div', { class: 'auth-desc' }, '正在检查保险箱状态…')
    ])
  );
}

function renderSetup() {
  const container = el('div', { class: 'auth-container' });
  const card = el('div', { class: 'auth-card' });
  const errDiv = el('div', { class: 'error-text' });
  const pwMeter = createPasswordInputWithMeter('设置主密码（至少 8 位）');
  const pwd1 = pwMeter.input;
  const pwd2 = el('input', { type: 'password', class: 'form-input', placeholder: '确认主密码' });
  const rememberCb = el('input', { type: 'checkbox' });
  rememberCb.checked = false; // 默认不勾选，符合最高安全基线
  let submitting = false;

  const vaultName = getCurrentVaultName('默认保险箱');
  const vaultPill = createVaultPill({
    style: 'margin: 0 auto 16px auto; width: fit-content;',
    title: '切换保险箱'
  });

  const submit = async () => {
    if (submitting) return;
    const p1 = pwd1.value, p2 = pwd2.value;
    const rem = rememberCb.checked;
    errDiv.textContent = '';
    const check = checkPasswordStrength(p1);
    if (!check.valid) { errDiv.textContent = check.text; return; }
    if (p1 !== p2) { errDiv.textContent = '两次输入的密码不一致'; return; }
    submitting = true;
    btn.disabled = true; btn.textContent = '创建中…';
    try {
      const code = await invoke('setup_password', { password: p1, remember: rem });
      state.pendingRecoveryCode = code;
      state.entries = [];
      state.hasSavedPassword = rem;
      await loadVaultsInfo();
      state.screen = 'recovery-code';
      render();
    } catch (e) {
      errDiv.textContent = e || '创建失败';
      btn.disabled = false; btn.textContent = '创建并解锁';
      submitting = false;
    }
  };
  pwd1.addEventListener('keydown', e => { if (e.key === 'Enter') pwd2.focus(); });
  pwd2.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  const btn = el('button', { class: 'btn btn-primary', onclick: submit }, '创建并解锁');

  card.append(
    vaultPill,
    el('div', { class: 'lock-icon' }, '🔒'),
    el('div', { class: 'auth-title' }, `初始化「${vaultName}」`),
    el('div', { class: 'auth-desc' }, '密码用于加密派生主密钥，请设置 8 位以上高强度密码。\n若忘记密码，仅可通过恢复码重置。'),
    ...pwMeter.elements,
    pwd2,
    el('label', { class: 'form-checkbox' }, [rememberCb, ' 记住此保险箱密码']),
    el('div', { class: 'form-checkbox-hint' }, '🛡️ 仅建议在个人私有电脑开启。公用或多人设备建议保持关闭以防钥匙串凭据被访问。'),
    errDiv, btn
  );
  container.appendChild(card);
  setTimeout(() => pwd1.focus(), 50);
  return container;
}

function startLockoutCountdown(seconds, btn, input, errEl) {
  if (state.lockoutInterval) clearInterval(state.lockoutInterval);
  state.lockoutRemaining = seconds;
  input.disabled = true;
  btn.disabled = true;

  const update = () => {
    if (state.lockoutRemaining <= 0) {
      clearInterval(state.lockoutInterval);
      state.lockoutInterval = null;
      input.disabled = false;
      btn.disabled = false;
      btn.textContent = '解锁';
      errEl.textContent = '安全冷却结束，请重新输入密码';
      input.focus();
    } else {
      btn.textContent = `安全锁定中 (${state.lockoutRemaining}s)`;
      errEl.textContent = `⚠️ 输错次数过多，触发防暴力破解保护，请等待 ${state.lockoutRemaining} 秒后再试`;
      state.lockoutRemaining--;
    }
  };

  update();
  state.lockoutInterval = setInterval(update, 1000);
}

function renderUnlock() {
  const container = el('div', { class: 'auth-container' });
  const card = el('div', { class: 'auth-card' });
  const errDiv = el('div', { class: 'error-text' });
  const pwd = el('input', { type: 'password', class: 'form-input', placeholder: '输入密码' });
  const rememberCb = el('input', { type: 'checkbox' });
  rememberCb.checked = !!state.hasSavedPassword;

  let unlocking = false;
  const unlockBtn = el('button', { class: 'btn btn-primary', onclick: () => doUnlock() }, '解锁');

  const vaultName = getCurrentVaultName('默认保险箱');
  const vaultPill = createVaultPill({
    style: 'margin: 0 auto 16px auto; width: fit-content;',
    title: '切换保险箱'
  });

  const doUnlock = async () => {
    if (unlocking || state.lockoutRemaining > 0) return;
    const p = pwd.value;
    errDiv.textContent = '';
    if (!p) { errDiv.textContent = '请输入密码'; return; }
    unlocking = true;
    unlockBtn.disabled = true;
    unlockBtn.textContent = '正在解锁…';
    try {
      const entries = await invoke('unlock', { password: p, remember: rememberCb.checked });
      state.entries = entries;
      state.hasSavedPassword = rememberCb.checked;
      if (state.currentVault) state.currentVault.is_unlocked = true;
      if (state.lockoutInterval) { clearInterval(state.lockoutInterval); state.lockoutInterval = null; }
      state.lockoutRemaining = 0;
      enterMain();
    } catch (e) {
      const errStr = String(e || '解锁失败');
      errDiv.textContent = errStr;
      unlockBtn.disabled = false;
      unlockBtn.textContent = '解锁';
      unlocking = false;

      // 提取剩余冷却秒数，触发倒计时 UI
      const match = errStr.match(/请等待\s*(\d+)\s*秒/);
      if (match) {
        startLockoutCountdown(parseInt(match[1]), unlockBtn, pwd, errDiv);
      }
    }
  };

  const keychainBtn = el('button', {
    class: 'btn bio-btn',
    onclick: () => doKeychainUnlock()
  }, '⚡️ 使用已记住的密码解锁');

  const doKeychainUnlock = async () => {
    if (unlocking || state.lockoutRemaining > 0) return;
    unlocking = true;
    errDiv.textContent = '';
    keychainBtn.disabled = true;
    keychainBtn.textContent = '正在解锁…';
    try {
      const entries = await invoke('unlock_with_keychain');
      state.entries = entries;
      if (state.currentVault) state.currentVault.is_unlocked = true;
      enterMain();
    } catch (e) {
      const errStr = String(e || '解锁失败，请输入密码');
      errDiv.textContent = errStr;
      keychainBtn.disabled = false;
      keychainBtn.textContent = '⚡️ 使用已记住的密码解锁';
      unlocking = false;

      const match = errStr.match(/请等待\s*(\d+)\s*秒/);
      if (match) {
        startLockoutCountdown(parseInt(match[1]), unlockBtn, pwd, errDiv);
      }
    }
  };

  const goRecovery = () => {
    state.recoveryStep = 1;
    state.recoveryCodeInput = '';
    state.screen = 'recovery-flow';
    render();
  };
  pwd.addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });

  card.append(
    vaultPill,
    el('div', { class: 'lock-icon' }, '🔓'),
    el('div', { class: 'auth-title' }, `解锁「${vaultName}」`),
    pwd,
    el('label', { class: 'form-checkbox' }, [rememberCb, ' 记住密码']),
    errDiv,
    unlockBtn
  );
  if (state.hasSavedPassword) {
    card.append(
      el('div', { class: 'auth-divider' }, el('span', {}, '或')),
      keychainBtn
    );
  }
  card.append(el('button', { class: 'link-btn', onclick: goRecovery }, '忘记密码？用恢复码找回'));
  container.appendChild(card);

  if (state.lockoutRemaining > 0) {
    startLockoutCountdown(state.lockoutRemaining, unlockBtn, pwd, errDiv);
  } else {
    setTimeout(() => pwd.focus(), 50);
  }
  return container;
}

function renderRecoveryCode() {
  const container = el('div', { class: 'auth-container' });
  const card = el('div', { class: 'auth-card' });
  const copyBtn = el('button', {
    class: 'btn btn-secondary',
    style: 'margin-bottom:12px;',
    onclick: async () => {
      try {
        await navigator.clipboard.writeText(state.pendingRecoveryCode);
        showToast('恢复码已复制');
      } catch { showToast('复制失败，请手动复制', true); }
    }
  }, '📋 复制恢复码');
  const done = () => { state.pendingRecoveryCode = ''; enterMain(); };

  card.append(
    el('div', { class: 'lock-icon' }, '🛡️'),
    el('div', { class: 'auth-title' }, '请保存您的恢复码'),
    el('div', { class: 'auth-desc' }, '如果忘记密码，您可以使用此恢复码重置密码。'),
    el('div', { class: 'recovery-warning' }, '⚠️ 恢复码只显示一次！请务必抄写或截图保存在安全的地方，丢失将无法找回。'),
    el('div', { class: 'recovery-code-box' }, state.pendingRecoveryCode),
    copyBtn,
    el('button', { class: 'btn btn-primary', onclick: done }, '我已保存，进入保险箱')
  );
  container.appendChild(card);
  return container;
}

function renderRecoveryFlow() {
  const container = el('div', { class: 'auth-container' });
  const card = el('div', { class: 'auth-card' });
  const steps = el('div', { class: 'steps' });
  for (let i = 1; i <= 3; i++) steps.appendChild(el('div', { class: 'step-dot' + (i <= state.recoveryStep ? ' active' : '') }));
  const errDiv = el('div', { class: 'error-text' });

  if (state.recoveryStep === 1) {
    const codeInput = el('input', { class: 'form-input', placeholder: '请输入恢复码' });
    codeInput.addEventListener('keydown', e => { if (e.key === 'Enter') next(); });
    const next = () => {
      if (!codeInput.value.trim()) { errDiv.textContent = '请输入恢复码'; return; }
      state.recoveryCodeInput = codeInput.value.trim();
      state.recoveryStep = 2;
      render();
    };
    card.append(
      el('div', { class: 'lock-icon' }, '🔑'),
      el('div', { class: 'auth-title' }, '使用恢复码重置'),
      el('div', { class: 'auth-desc' }, '第 1 步：输入您保存的恢复码'),
      steps, codeInput, errDiv,
      el('button', { class: 'btn btn-primary', onclick: next }, '下一步'),
      el('br'),
      el('button', { class: 'link-btn', onclick: () => { state.screen = 'unlock'; render(); } }, '返回解锁')
    );
    setTimeout(() => codeInput.focus(), 50);
  } else if (state.recoveryStep === 2) {
    const pwMeter = createPasswordInputWithMeter('设置新密码（至少 8 位）');
    const p1 = pwMeter.input;
    const p2 = el('input', { type: 'password', class: 'form-input', placeholder: '确认新密码' });
    p1.addEventListener('keydown', e => { if (e.key === 'Enter') p2.focus(); });
    const next = async () => {
      errDiv.textContent = '';
      const check = checkPasswordStrength(p1.value);
      if (!check.valid) { errDiv.textContent = check.text; return; }
      if (p1.value !== p2.value) { errDiv.textContent = '两次输入的密码不一致'; return; }
      try {
        const code = await invoke('recover_password', { recoveryCode: state.recoveryCodeInput, newPassword: p1.value });
        state.pendingRecoveryCode = code;
        state.recoveryStep = 3;
        render();
      } catch (e) { errDiv.textContent = e || '恢复失败，请检查恢复码'; }
    };
    p2.addEventListener('keydown', e => { if (e.key === 'Enter') next(); });
    card.append(
      el('div', { class: 'lock-icon' }, '🔒'),
      el('div', { class: 'auth-title' }, '设置新密码'),
      el('div', { class: 'auth-desc' }, '第 2 步：设置新的 8 位以上高强度密码'),
      steps, ...pwMeter.elements, p2, errDiv,
      el('button', { class: 'btn btn-primary', onclick: next }, '确认重置')
    );
    setTimeout(() => p1.focus(), 50);
  } else {
    const copyBtn = el('button', {
      class: 'btn btn-secondary', style: 'margin-bottom:12px;',
      onclick: async () => {
        try { await navigator.clipboard.writeText(state.pendingRecoveryCode); showToast('已复制'); } catch {}
      }
    }, '📋 复制');
    const done = async () => {
      try {
        const entries = await invoke('list_entries');
        state.entries = entries;
        state.pendingRecoveryCode = '';
        state.recoveryStep = 1;
        enterMain();
      } catch {
        state.screen = 'unlock';
        render();
      }
    };
    card.append(
      el('div', { class: 'lock-icon' }, '✅'),
      el('div', { class: 'auth-title' }, '密码重置成功'),
      el('div', { class: 'auth-desc' }, '第 3 步：请保存新的恢复码'),
      el('div', { class: 'recovery-warning' }, '⚠️ 旧恢复码已失效，请妥善保存新恢复码。'),
      steps,
      el('div', { class: 'recovery-code-box' }, state.pendingRecoveryCode),
      copyBtn,
      el('button', { class: 'btn btn-primary', onclick: done }, '我已保存')
    );
  }
  container.appendChild(card);
  return container;
}

// ===== Main Screen =====
function enterMain() {
  state.screen = 'main';
  state.multiSelectMode = false;
  state.selectedIds.clear();
  state.searchQuery = '';
  state.sortBy = 'time';
  state.sortAsc = false;
  resetIdleTimer();
  render();
}

function renderMain() {
  const wrapper = el('div', { style: 'display:flex;flex-direction:column;height:100%;' });
  applyFilterAndSort();
  const totalCount = state.entries.length;
  const selectedCount = state.selectedIds.size;

  // Top bar with Vault Switcher Pill
  const topbar = el('div', { class: 'topbar' });
  const vaultPill = createVaultPill({
    id: 'vaultPill',
    isMain: true,
    title: '切换或管理保险箱'
  });
  const left = el('div', { class: 'topbar-left' }, [vaultPill]);

  const searchInput = el('input', {
    type: 'text', class: 'search-input',
    placeholder: '搜索文件…', value: state.searchQuery
  });
  searchInput.addEventListener('input', e => {
    state.searchQuery = e.target.value;
    const list = $('#listContainer');
    if (list) renderListInto(list);
    updateCountLabel();
  });
  const center = el('div', { class: 'topbar-center' }, [
    el('div', { class: 'search-box' }, [
      el('span', { class: 'search-icon' }, '🔍'),
      searchInput
    ])
  ]);
  const countLabel = el('span', { class: 'count-label', id: 'countLabel' });
  const multiBtn = el('button', {
    class: 'icon-btn' + (state.multiSelectMode ? ' active' : ''),
    title: '多选',
    onclick: () => {
      state.multiSelectMode = !state.multiSelectMode;
      if (!state.multiSelectMode) state.selectedIds.clear();
      render();
    }
  }, '☑️');
  const gearBtn = el('button', {
    id: 'gearBtn',
    class: 'icon-btn', title: '设置',
    onclick: e => toggleGearMenu(e)
  }, '⚙️');
  const addBtn = el('button', {
    id: 'addBtn',
    class: 'btn-add',
    title: '添加文件或文件夹',
    onclick: e => toggleAddMenu(e)
  }, [
    el('span', {}, '＋ 添加'),
    el('span', { class: 'arrow', html: CHEVRON_DOWN_SVG })
  ]);
  const lockBtnEl = el('button', { class: 'lock-btn', onclick: doLock }, '🔒 锁定');
  const right = el('div', { class: 'topbar-right' }, [countLabel, addBtn, multiBtn, gearBtn, lockBtnEl]);
  topbar.append(left, center, right);

  // Sort bar (only when there are files)
  const sortBar = el('div', { class: 'sort-bar', id: 'sortBar', style: totalCount > 0 ? '' : 'display:none;' });
  sortBar.append(el('span', { class: 'sort-label' }, '排序：'));
  const segGroup = el('div', { class: 'seg-group' });
  for (const [key, label] of [['category','分类'],['time','时间'],['size','大小']]) {
    segGroup.appendChild(el('button', {
      class: 'seg-btn' + (state.sortBy === key ? ' active' : ''),
      onclick: () => {
        if (state.sortBy === key) state.sortAsc = !state.sortAsc;
        else { state.sortBy = key; state.sortAsc = false; }
        render();
      }
    }, label));
  }
  sortBar.appendChild(segGroup);
  sortBar.appendChild(el('button', {
    class: 'icon-btn',
    title: state.sortAsc ? '升序' : '降序',
    style: 'margin-left:4px;width:28px;height:28px;font-size:13px;',
    onclick: () => { state.sortAsc = !state.sortAsc; render(); }
  }, state.sortAsc ? '↑' : '↓'));

  // Action bar
  const actionBar = el('div', {
    class: 'action-bar',
    style: state.multiSelectMode && selectedCount > 0 ? '' : 'display:none;'
  });
  actionBar.append(
    el('span', {}, `已选 ${selectedCount} 项`),
    el('div', { class: 'action-bar-spacer' }),
    el('button', { class: 'btn btn-danger', onclick: deleteSelected }, '🗑 删除'),
    el('button', { class: 'btn btn-outline', onclick: exportSelected }, '⤴ 导出'),
    el('button', {
      class: 'btn btn-ghost',
      onclick: () => { state.selectedIds.clear(); render(); }
    }, '取消选择')
  );

  const listContainer = el('div', { class: 'list-container', id: 'listContainer' });
  let totalBytes = 0;
  for (const e of state.entries) totalBytes += (e.size || 0);
  const statusBar = el('div', { class: 'status-bar' }, [
    el('span', {}, `${totalCount} 个项目 · 已用 ${formatSize(totalBytes)}`)
  ]);
  wrapper.append(topbar, sortBar, listContainer, actionBar, statusBar);

  updateCountLabel();
  setTimeout(() => renderListInto(listContainer), 0);
  return wrapper;
}

function updateCountLabel() {
  const label = $('#countLabel');
  if (!label) return;
  const total = state.entries.length;
  const sel = state.selectedIds.size;
  label.textContent = state.multiSelectMode && sel > 0 ? `已选 ${sel}/${total}` : `共 ${total} 项`;
}

function applyFilterAndSort() {
  let list = state.entries.slice();
  const q = state.searchQuery.trim().toLowerCase();
  if (q) {
    list = list.filter(e => {
      if (e.name.toLowerCase().includes(q)) return true;
      if (getCategory(e.name).toLowerCase().includes(q)) return true;
      if (e.original_path && e.original_path.toLowerCase().includes(q)) return true;
      return false;
    });
  }
  list.sort((a, b) => {
    let cmp = 0;
    if (state.sortBy === 'category') {
      cmp = getCategory(a.name).localeCompare(getCategory(b.name), 'zh-CN');
      if (cmp === 0) cmp = a.name.localeCompare(b.name, 'zh-CN');
    } else if (state.sortBy === 'size') {
      cmp = a.size - b.size;
    } else {
      cmp = a.added_at - b.added_at;
    }
    return state.sortAsc ? cmp : -cmp;
  });
  state.filteredEntries = list;
}

function renderListInto(container) {
  container.innerHTML = '';
  applyFilterAndSort();
  if (state.entries.length === 0) {
    const chooseFileBtn = el('button', {
      class: 'btn btn-primary',
      style: 'width:auto;',
      onclick: () => chooseAndAdd(false)
    }, '📄 选择文件存入');
    const chooseFolderBtn = el('button', {
      class: 'btn btn-outline',
      style: 'width:auto;',
      onclick: () => chooseAndAdd(true)
    }, '📁 选择文件夹存入');
    container.appendChild(el('div', { class: 'empty-state' }, [
      el('div', { class: 'empty-icon' }, '🛡️'),
      el('div', { class: 'empty-text' }, '拖拽文件或文件夹到此处加密存入'),
      el('div', { class: 'empty-sub' }, '文件将被 AES-256-GCM 流式分块加密，仅可通过密码访问'),
      el('div', { style: 'display:flex;gap:10px;margin-top:16px;' }, [chooseFileBtn, chooseFolderBtn])
    ]));
    return;
  }
  if (state.filteredEntries.length === 0) {
    container.appendChild(el('div', { class: 'no-results' }, [
      el('div', { class: 'no-results-icon' }, '🔍'),
      el('div', {}, '没有找到匹配的文件')
    ]));
    return;
  }
  for (const entry of state.filteredEntries) {
    container.appendChild(renderFileItem(entry));
  }
}

function renderFileItem(entry) {
  const isFolder = entry.kind === 'folder';
  const isSelected = state.selectedIds.has(entry.id);
  const category = getCategory(entry.name);
  let iconClass = 'other';
  let iconChar = '📄';
  if (isFolder) { iconClass = 'folder'; iconChar = '📁'; }
  else if (category === '图片') { iconClass = 'image'; iconChar = '🖼️'; }
  else if (category === '视频' || category === '音频') { iconClass = 'media'; iconChar = '🎬'; }
  else if (category === '文档') { iconClass = 'document'; iconChar = '📄'; }
  else if (category === '压缩包') { iconClass = 'archive'; iconChar = '📦'; }
  else if (category === '代码') { iconClass = 'code'; iconChar = '💻'; }

  const row = el('div', {
    class: 'file-item' + (isSelected ? ' selected' : ''),
    'data-id': entry.id,
    draggable: 'true'
  });
  if (state.multiSelectMode) {
    row.appendChild(el('div', {
      class: 'file-checkbox' + (isSelected ? ' checked' : ''),
      onclick: e => { e.stopPropagation(); toggleSelect(entry.id); }
    }, isSelected ? '✓' : ''));
  }
  row.appendChild(el('div', { class: 'file-icon ' + iconClass }, iconChar));
  const meta = `${category} · ${formatSize(entry.size)} · ${formatDate(entry.added_at)}`;
  row.appendChild(el('div', { class: 'file-info' }, [
    el('div', { class: 'file-name', title: entry.name }, entry.name),
    el('div', { class: 'file-meta' }, meta)
  ]));
  const actions = el('div', { class: 'file-actions' });
  const mkBtn = (emoji, title, handler, danger) => actions.appendChild(el('button', {
    class: 'file-action-btn' + (danger ? ' danger' : ''),
    title, onclick: e => { e.stopPropagation(); handler(); }
  }, emoji));
  mkBtn('✏️', '重命名', () => showRenameModal(entry));
  mkBtn('↩', '还原到原位置', () => restoreEntry(entry.id));
  mkBtn('👁', '打开', () => openEntry(entry.id));
  mkBtn('⤴', '导出', () => exportEntry(entry));
  mkBtn('🗑', '删除', () => deleteEntry(entry), true);
  row.appendChild(actions);

  row.addEventListener('click', e => {
    if (e.target.closest('.file-actions') || e.target.closest('.file-checkbox')) return;
    if (state.multiSelectMode) {
      toggleSelect(entry.id);
    } else {
      state.selectedIds.clear();
      state.selectedIds.add(entry.id);
      $$('.file-item').forEach(el => el.classList.toggle('selected', el.dataset.id === entry.id));
      updateCountLabel();
    }
  });
  row.addEventListener('dblclick', e => {
    if (e.target.closest('.file-actions') || e.target.closest('.file-checkbox')) return;
    openEntry(entry.id);
  });
  row.addEventListener('contextmenu', e => {
    e.preventDefault();
    state.contextMenuTargetId = entry.id;
    showContextMenu(e.clientX, e.clientY);
  });
  row.addEventListener('dragstart', async e => {
    try {
      const path = await invoke('temporary_export_url', { id: entry.id });
      e.dataTransfer.setData('text/uri-list', 'file://' + path);
      e.dataTransfer.effectAllowed = 'copy';
    } catch (err) { showError('拖拽失败: ' + err); }
  });
  return row;
}

function toggleSelect(id) {
  if (state.selectedIds.has(id)) state.selectedIds.delete(id);
  else state.selectedIds.add(id);
  render();
}

// ---- File ops ----
function showRenameModal(entry) {
  const errDiv = el('div', { class: 'error-text' });
  const nameInput = el('input', {
    type: 'text',
    class: 'form-input',
    value: entry.name,
    placeholder: '输入新名称'
  });

  const submit = async () => {
    const newName = nameInput.value.trim();
    errDiv.textContent = '';
    if (!newName) { errDiv.textContent = '条目名称不能为空'; return; }
    if (newName === entry.name) { closeModal(); return; }
    try {
      const updated = await invoke('rename_entry', { id: entry.id, newName });
      const idx = state.entries.findIndex(e => e.id === entry.id);
      if (idx !== -1) state.entries[idx] = updated;
      closeModal();
      showToast('重命名成功');
      render();
    } catch (e) {
      errDiv.textContent = e || '重命名失败';
    }
  };

  nameInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') submit();
  });

  const modal = el('div', { class: 'modal' }, [
    el('div', { class: 'modal-title' }, '重命名条目'),
    el('div', { class: 'modal-desc' }, `为「${entry.name}」输入新的文件或文件夹名称。`),
    nameInput,
    errDiv,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn btn-ghost', onclick: closeModal }, '取消'),
      el('button', { class: 'btn btn-primary', style: 'width:auto;padding:8px 20px;', onclick: submit }, '确定')
    ])
  ]);
  showModal(modal);
  setTimeout(() => {
    nameInput.focus();
    const dotIdx = entry.name.lastIndexOf('.');
    if (dotIdx > 0 && entry.kind !== 'folder') {
      nameInput.setSelectionRange(0, dotIdx);
    } else {
      nameInput.select();
    }
  }, 50);
}

async function openEntry(id) {
  try { await invoke('open_entry', { id }); }
  catch (e) { showError('打开失败: ' + e); }
}

async function exportEntry(entry) {
  try {
    const savePath = await invoke('pick_save_path', { defaultName: entry.name }).catch(() => null);
    if (!savePath) return;
    await invoke('export_entry', { id: entry.id, targetPath: savePath });
    showToast('导出成功');
  } catch (e) { showError('导出失败: ' + e); }
}

async function exportSelected() {
  const ids = Array.from(state.selectedIds);
  if (ids.length === 0) return;
  try {
    const picked = await invoke('pick_paths', { directory: true, multiple: false }).catch(() => null);
    const targetDir = picked && picked.length > 0 ? picked[0] : null;
    if (!targetDir) return;
    await invoke('export_entries_to_dir', { ids, dir: targetDir });
    showToast(`已导出 ${ids.length} 项`);
    state.selectedIds.clear();
    state.multiSelectMode = false;
    render();
  } catch (e) { showError('导出失败: ' + e); }
}

async function restoreEntry(id) {
  try {
    await invoke('restore_entry', { id });
    state.entries = await invoke('list_entries');
    showToast('已还原到原位置');
    render();
  } catch (e) { showError('还原失败: ' + e); }
}

async function deleteEntry(entry) {
  showConfirm(`确定要删除「${entry.name}」吗？密文文件会从保险箱中移除，删除后不可恢复。`, async () => {
    try {
      await invoke('delete_entry', { id: entry.id });
      state.entries = await invoke('list_entries');
      state.selectedIds.delete(entry.id);
      showToast('已删除，密文文件已移除');
      render();
    } catch (e) { showError('删除失败: ' + e); }
  });
}

async function deleteSelected() {
  const ids = Array.from(state.selectedIds);
  if (ids.length === 0) return;
  showConfirm(`确定要删除选中的 ${ids.length} 项吗？密文文件会从保险箱中移除，删除后不可恢复。`, async () => {
    try {
      await invoke('delete_entries', { ids });
      state.entries = await invoke('list_entries');
      state.selectedIds.clear();
      state.multiSelectMode = false;
      showToast('已删除，密文文件已移除');
      render();
    } catch (e) { showError('删除失败: ' + e); }
  });
}

async function doLock() {
  try { await invoke('lock'); } catch {}
  state.entries = [];
  state.selectedIds.clear();
  state.multiSelectMode = false;
  state.searchQuery = '';
  if (state.currentVault) state.currentVault.is_unlocked = false;
  state.screen = 'unlock';
  render();
}

// ---- Drag & Drop into app ----
function setupDragDrop() {
  const container = $('#listContainer');
  if (!container) return;
  let dragDepth = 0;
  container.addEventListener('dragenter', e => {
    e.preventDefault();
    dragDepth++;
    container.classList.add('drag-over');
    if (!container.querySelector('.drag-hint')) {
      container.appendChild(el('div', { class: 'drag-hint' }, '松开以加入保险箱'));
    }
  });
  container.addEventListener('dragover', e => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });
  container.addEventListener('dragleave', e => {
    dragDepth--;
    if (dragDepth <= 0) {
      dragDepth = 0;
      container.classList.remove('drag-over');
      const hint = container.querySelector('.drag-hint');
      if (hint) hint.remove();
    }
  });
  container.addEventListener('drop', e => {
    e.preventDefault();
    dragDepth = 0;
    container.classList.remove('drag-over');
    const hint = container.querySelector('.drag-hint');
    if (hint) hint.remove();
  });
}

async function initDragDropListener() {
  try {
    await listen('tauri://drag-drop', async event => {
      let raw = [];
      if (Array.isArray(event.payload)) {
        raw = event.payload;
      } else if (event.payload && Array.isArray(event.payload.paths)) {
        raw = event.payload.paths;
      } else if (event.payload && Array.isArray(event.payload.urls)) {
        raw = event.payload.urls;
      }
      if (raw.length === 0) return;
      const paths = raw.map(u => {
        let p = u;
        if (typeof p === 'string' && p.startsWith('file://')) {
          p = decodeURIComponent(p.slice(7));
          if (p.startsWith('/') && /^[A-Za-z]:/.test(p.slice(1))) p = p.slice(1);
        }
        return p;
      });
      await addFilesByPaths(paths);
    });
  } catch {}
}

window.addEventListener('DOMContentLoaded', () => {
  document.addEventListener('drop', async e => {
    if (state.screen !== 'main') return;
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const paths = [];
      for (let i = 0; i < e.dataTransfer.files.length; i++) {
        const f = e.dataTransfer.files[i];
        if (f.path) paths.push(f.path);
      }
      if (paths.length > 0) {
        e.preventDefault();
        await addFilesByPaths(paths);
      }
    }
  });
  document.addEventListener('dragover', e => {
    if (state.screen === 'main') e.preventDefault();
  });
});

async function addFilesByPaths(paths) {
  try {
    showToast(`正在加密存入 ${paths.length} 个文件…`);
    const added = await invoke('add_files', { paths });
    state.entries = await invoke('list_entries');
    showToast(`已加密存入 ${added.length} 项`);
    render();
  } catch (e) { showError('添加失败: ' + e); }
}

// ---- Context menu ----
function showContextMenu(x, y) {
  const menu = $('#contextMenu');
  menu.classList.add('visible');
  const maxX = window.innerWidth - 200;
  const maxY = window.innerHeight - 250;
  menu.style.left = Math.min(x, maxX) + 'px';
  menu.style.top = Math.min(y, maxY) + 'px';
}
function hideContextMenu() { $('#contextMenu').classList.remove('visible'); }

function hideAllMenus() {
  hideContextMenu();
  const gm = $('#gearMenu');
  if (gm) gm.classList.remove('visible');
  hideAddMenu();
  hideVaultMenu();
}

document.addEventListener('click', e => {
  const item = e.target.closest('.context-menu-item');
  if (item) {
    const action = item.dataset.action;
    const id = state.contextMenuTargetId;
    hideContextMenu();
    if (!id) return;
    const entry = state.entries.find(x => x.id === id);
    if (!entry) return;
    if (action === 'open') openEntry(id);
    else if (action === 'rename') showRenameModal(entry);
    else if (action === 'export') exportEntry(entry);
    else if (action === 'restore') restoreEntry(id);
    else if (action === 'delete') deleteEntry(entry);
    return;
  }
  if (!e.target.closest('#contextMenu')) hideContextMenu();

  const aItem = e.target.closest('#addMenu .dropdown-item');
  if (aItem) {
    const act = aItem.dataset.action;
    hideAddMenu();
    if (act === 'add-files') chooseAndAdd(false);
    else if (act === 'add-folders') chooseAndAdd(true);
    return;
  }
  if (!e.target.closest('#addMenu') && !e.target.closest('#addBtn')) hideAddMenu();

  const vItem = e.target.closest('#vaultMenu .dropdown-item');
  if (vItem) {
    const act = vItem.dataset.action;
    hideVaultMenu();
    if (act === 'create-vault') showCreateVaultModal();
    else if (act === 'rename-vault') showRenameVaultModal();
    else if (act === 'delete-vault') showDeleteVaultConfirm();
    return;
  }
  if (!e.target.closest('#vaultMenu') && !e.target.closest('.vault-pill')) hideVaultMenu();

  const sub = e.target.closest('.submenu-item');
  if (sub) {
    const val = parseInt(sub.dataset.val);
    setAutoLock(val);
    hideGearMenu();
    return;
  }
  const gItem = e.target.closest('#gearMenu .dropdown-item');
  if (gItem) {
    const action = gItem.dataset.action;
    if (action === 'changepw') { hideGearMenu(); showChangePasswordModal(); }
    else if (action === 'shred-temp') {
      hideGearMenu();
      (async () => {
        try {
          await invoke('clear_temp');
          showToast('已清理所有临时预览文件');
        } catch (err) { showError('清理失败: ' + err); }
      })();
    }
    else if (action === 'forget-pw') {
      hideGearMenu();
      showConfirm('确定要从系统钥匙串/凭据管理器中清除已保存的密码吗？\n清除后下次登录需手动输入密码。', async () => {
        try {
          await invoke('forget_saved_password');
          state.hasSavedPassword = false;
          if (state.currentVault) state.currentVault.has_saved_password = false;
          showToast('已清除系统凭据库中的密码');
          render();
        } catch (err) { showError('清除失败: ' + err); }
      });
    }
    else if (action === 'reset') { hideGearMenu(); showResetConfirm(); }
    else if (action === 'autolock') { gItem.classList.toggle('open'); }
    return;
  }
  if (!e.target.closest('#gearMenu') && !e.target.closest('#gearBtn')) hideGearMenu();
});

// ---- Add menu ----
function toggleAddMenu(e) {
  if (e) {
    e.stopPropagation();
    e.preventDefault();
  }
  const menu = $('#addMenu');
  if (menu.classList.contains('visible')) { hideAddMenu(); return; }
  hideAllMenus();
  const btn = e ? (e.currentTarget || e.target.closest('#addBtn')) : $('#addBtn');
  if (btn) btn.classList.add('open');
  const rect = btn.getBoundingClientRect();
  menu.classList.add('visible');
  const menuRect = menu.getBoundingClientRect();
  let x = rect.left;
  let y = rect.bottom + 6;
  if (x + menuRect.width > window.innerWidth) x = rect.right - menuRect.width;
  if (y + menuRect.height > window.innerHeight) y = rect.top - menuRect.height - 6;
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
}
function hideAddMenu() {
  const m = $('#addMenu');
  if (m) m.classList.remove('visible');
  const ab = $('#addBtn');
  if (ab) ab.classList.remove('open');
}

async function chooseAndAdd(directory) {
  hideAddMenu();
  try {
    const paths = await invoke('pick_paths', { directory: !!directory, multiple: true }).catch(() => null);
    if (paths && paths.length > 0) await addFilesByPaths(paths);
  } catch (err) { showError('添加失败: ' + err); }
}

// ---- Vault Switcher menu ----
function toggleVaultMenu(e) {
  if (e) {
    e.stopPropagation();
    e.preventDefault();
  }
  const menu = $('#vaultMenu');
  if (menu.classList.contains('visible')) { hideVaultMenu(); return; }
  hideAllMenus();

  const itemsContainer = $('#vaultListItems');
  itemsContainer.innerHTML = '';
  for (const v of state.vaults) {
    const isCurrent = state.currentVault && state.currentVault.id === v.id;
    const it = el('div', {
      class: 'dropdown-item' + (isCurrent ? ' active' : ''),
      onclick: () => switchVault(v.id)
    }, [
      el('span', { style: 'display:flex;align-items:center;gap:6px;' }, [
        el('span', { style: isCurrent ? 'color:var(--primary);font-weight:600;' : 'opacity:0;' }, '✓'),
        el('span', { style: isCurrent ? 'font-weight:600;' : '' }, v.name)
      ]),
      el('span', { style: 'font-size:11px;color:var(--text-secondary);' }, v.id === 'default' ? '默认' : '')
    ]);
    itemsContainer.appendChild(it);
  }

  const btn = e ? (e.currentTarget || e.target.closest('.vault-pill')) : $('#vaultPill');
  if (btn) btn.classList.add('open');
  const rect = btn.getBoundingClientRect();
  menu.classList.add('visible');
  const menuRect = menu.getBoundingClientRect();
  let x = rect.left;
  let y = rect.bottom + 6;
  if (x + menuRect.width > window.innerWidth) x = rect.right - menuRect.width;
  if (y + menuRect.height > window.innerHeight) y = rect.top - menuRect.height - 6;
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
}
function hideVaultMenu() {
  const m = $('#vaultMenu');
  if (m) m.classList.remove('visible');
  document.querySelectorAll('.vault-pill').forEach(p => p.classList.remove('open'));
}

function showCreateVaultModal() {
  const errDiv = el('div', { class: 'error-text' });
  const nameInput = el('input', { type: 'text', class: 'form-input', placeholder: '保险箱名称（如：工作机密）' });
  const pwMeter = createPasswordInputWithMeter('设置主密码（至少 8 位）');
  const pwd1 = pwMeter.input;
  const pwd2 = el('input', { type: 'password', class: 'form-input', placeholder: '确认主密码' });
  const rememberCb = el('input', { type: 'checkbox' });
  rememberCb.checked = false;

  const submit = async () => {
    const name = nameInput.value.trim();
    const p1 = pwd1.value, p2 = pwd2.value;
    const rem = rememberCb.checked;
    errDiv.textContent = '';
    if (!name) { errDiv.textContent = '请输入保险箱名称'; return; }
    const check = checkPasswordStrength(p1);
    if (!check.valid) { errDiv.textContent = check.text; return; }
    if (p1 !== p2) { errDiv.textContent = '两次输入的密码不一致'; return; }

    try {
      const res = await invoke('create_vault', {
        name,
        password: p1,
        remember: rem
      });
      state.currentVault = res.vault;
      state.pendingRecoveryCode = res.recovery_code;
      state.entries = [];
      state.hasSavedPassword = rem;
      await loadVaultsInfo();
      closeModal();
      state.screen = 'recovery-code';
      render();
    } catch (e) {
      errDiv.textContent = e || '创建保险箱失败';
    }
  };

  nameInput.addEventListener('keydown', e => { if (e.key === 'Enter') pwd1.focus(); });
  pwd1.addEventListener('keydown', e => { if (e.key === 'Enter') pwd2.focus(); });
  pwd2.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });

  const modal = el('div', { class: 'modal' }, [
    el('div', { class: 'modal-title' }, '创建新保险箱'),
    el('div', { class: 'modal-desc' }, '每个保险箱拥有独立的数据目录、加密主密钥与密码保护。'),
    nameInput, ...pwMeter.elements, pwd2,
    el('label', { class: 'form-checkbox' }, [rememberCb, ' 记住此保险箱密码']),
    el('div', { class: 'form-checkbox-hint' }, '🛡️ 仅建议在个人专用电脑开启。'),
    errDiv,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn btn-ghost', onclick: closeModal }, '取消'),
      el('button', { class: 'btn btn-primary', style: 'width:auto;padding:8px 20px;', onclick: submit }, '创建并切换')
    ])
  ]);
  showModal(modal);
  setTimeout(() => nameInput.focus(), 50);
}

function showRenameVaultModal() {
  if (!state.currentVault) return;
  const errDiv = el('div', { class: 'error-text' });
  const nameInput = el('input', {
    type: 'text',
    class: 'form-input',
    value: state.currentVault.name,
    placeholder: '新保险箱名称'
  });

  const submit = async () => {
    const newName = nameInput.value.trim();
    errDiv.textContent = '';
    if (!newName) { errDiv.textContent = '名称不能为空'; return; }
    if (newName === state.currentVault.name) { closeModal(); return; }
    try {
      await invoke('rename_vault', { vaultId: state.currentVault.id, newName });
      state.currentVault.name = newName;
      await loadVaultsInfo();
      closeModal();
      showToast('保险箱已重命名');
      render();
    } catch (e) {
      errDiv.textContent = e || '重命名失败';
    }
  };

  nameInput.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });

  const modal = el('div', { class: 'modal' }, [
    el('div', { class: 'modal-title' }, '重命名当前保险箱'),
    el('div', { class: 'modal-desc' }, `为当前保险箱「${state.currentVault.name}」修改显示名称。`),
    nameInput,
    errDiv,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn btn-ghost', onclick: closeModal }, '取消'),
      el('button', { class: 'btn btn-primary', style: 'width:auto;padding:8px 20px;', onclick: submit }, '确定')
    ])
  ]);
  showModal(modal);
  setTimeout(() => { nameInput.focus(); nameInput.select(); }, 50);
}

function showDeleteVaultConfirm() {
  if (!state.currentVault) return;
  if (state.vaults.length <= 1) {
    showError('至少需要保留一个保险箱，无法删除');
    return;
  }
  showConfirm(`确定要彻底删除保险箱「${state.currentVault.name}」吗？\n该保险箱下的所有加密文件及密码将被永久清除，且无法恢复！`, async () => {
    try {
      const nextVault = await invoke('delete_vault', { vaultId: state.currentVault.id });
      state.currentVault = nextVault;
      state.entries = [];
      state.selectedIds.clear();
      state.multiSelectMode = false;
      await loadVaultsInfo();
      showToast('保险箱已删除，已自动切换');
      if (nextVault.exists) {
        state.screen = 'unlock';
      } else {
        state.screen = 'setup';
      }
      render();
    } catch (e) {
      showError('删除失败: ' + e);
    }
  });
}

// ---- Gear menu ----
function toggleGearMenu(e) {
  if (e) {
    e.stopPropagation();
    e.preventDefault();
  }
  const menu = $('#gearMenu');
  if (menu.classList.contains('visible')) { hideGearMenu(); return; }
  const btn = e ? (e.currentTarget || e.target) : $('#gearBtn');
  const rect = btn.getBoundingClientRect();
  menu.classList.add('visible');
  $$('#autoLockSubmenu .submenu-item').forEach(it => {
    it.classList.toggle('active', parseInt(it.dataset.val) === state.autoLockMinutes);
  });
  const menuRect = menu.getBoundingClientRect();
  let x = rect.right - menuRect.width;
  let y = rect.bottom + 6;
  if (x < 10) x = 10;
  if (y + menuRect.height > window.innerHeight) y = rect.top - menuRect.height - 6;
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
}
function hideGearMenu() { $('#gearMenu').classList.remove('visible'); }

async function setAutoLock(mins) {
  try {
    await invoke('set_auto_lock_minutes', { mins });
    state.autoLockMinutes = mins;
    showToast(mins === 0 ? '自动锁定已关闭' : `自动锁定：${mins} 分钟`);
  } catch (e) { showError('设置失败: ' + e); }
}

// ---- Modals ----
function showModal(contentEl) {
  closeModal();
  const overlay = el('div', { class: 'modal-overlay', id: 'modalOverlay' });
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
  overlay.appendChild(contentEl);
  document.body.appendChild(overlay);
  state.modalOpen = true;
}
function closeModal() {
  const o = $('#modalOverlay');
  if (o) o.remove();
  state.modalOpen = false;
}

function showConfirm(message, onConfirm) {
  const modal = el('div', { class: 'modal' }, [
    el('div', { class: 'modal-title' }, '确认操作'),
    el('div', { class: 'modal-desc' }, message),
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn btn-ghost', onclick: closeModal }, '取消'),
      el('button', {
        class: 'btn btn-danger',
        onclick: () => { closeModal(); onConfirm(); }
      }, '确定')
    ])
  ]);
  showModal(modal);
}

function showChangePasswordModal() {
  const errDiv = el('div', { class: 'error-text' });
  const oldP = el('input', { type: 'password', class: 'form-input', placeholder: '当前密码' });
  const pwMeter = createPasswordInputWithMeter('新主密码（至少 8 位）');
  const newP = pwMeter.input;
  const newP2 = el('input', { type: 'password', class: 'form-input', placeholder: '确认新密码' });

  const submit = async () => {
    errDiv.textContent = '';
    const o = oldP.value, n = newP.value, n2 = newP2.value;
    if (!o) { errDiv.textContent = '请输入当前密码'; return; }
    const check = checkPasswordStrength(n);
    if (!check.valid) { errDiv.textContent = check.text; return; }
    if (n !== n2) { errDiv.textContent = '两次输入的新密码不一致'; return; }
    try {
      const code = await invoke('change_password', { old: o, new: n });
      closeModal();
      state.pendingRecoveryCode = code;
      state.screen = 'recovery-code';
      render();
    } catch (e) { errDiv.textContent = e || '修改失败'; }
  };

  oldP.addEventListener('keydown', e => { if (e.key === 'Enter') newP.focus(); });
  newP.addEventListener('keydown', e => { if (e.key === 'Enter') newP2.focus(); });
  newP2.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });

  const modal = el('div', { class: 'modal' }, [
    el('div', { class: 'modal-title' }, '修改主密码'),
    el('div', { class: 'modal-desc' }, '密码修改成功后将重新包装加密主密钥，并生成新的安全恢复码。'),
    oldP, ...pwMeter.elements, newP2,
    errDiv,
    el('div', { class: 'modal-actions' }, [
      el('button', { class: 'btn btn-ghost', onclick: closeModal }, '取消'),
      el('button', { class: 'btn btn-primary', style: 'width:auto;padding:8px 20px;', onclick: submit }, '确认修改')
    ])
  ]);
  showModal(modal);
  setTimeout(() => oldP.focus(), 50);
}

function showResetConfirm() {
  const vaultName = state.currentVault ? state.currentVault.name : '当前保险箱';
  showConfirm(`确定要清空「${vaultName}」吗？该保险箱内的所有加密文件将被删除，此操作不可恢复！`, async () => {
    try {
      await invoke('reset_vault');
      state.entries = [];
      state.hasSavedPassword = false;
      await loadVaultsInfo();
      state.screen = 'setup';
      render();
      showToast('保险箱已清空');
    } catch (e) { showError('清空失败: ' + e); }
  });
}

// ---- Init ----
async function init() {
  render();
  try {
    await loadVaultsInfo();
    const exists = await invoke('vault_exists');
    if (exists) {
      state.hasSavedPassword = await invoke('has_saved_password');
      if (state.hasSavedPassword) {
        try {
          const entries = await invoke('unlock_with_keychain');
          state.entries = entries;
          if (state.currentVault) state.currentVault.is_unlocked = true;
          state.autoLockMinutes = await invoke('get_auto_lock_minutes');
          enterMain();
          startIdleMonitor();
          initDragDropListener();
          initAutoLockListener();
          return;
        } catch (e) {
          console.warn('记住密码自动解锁失败，展示手动解锁界面:', e);
        }
      }
      state.screen = 'unlock';
    } else {
      state.screen = 'setup';
    }
    state.autoLockMinutes = await invoke('get_auto_lock_minutes');
  } catch (e) {
    state.screen = 'setup';
  }
  render();
  startIdleMonitor();
  initDragDropListener();
  initAutoLockListener();
}

// Keyboard shortcuts
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    hideAllMenus();
    if (state.modalOpen) closeModal();
  }
  // Cmd/Ctrl+L to lock
  if ((e.metaKey || e.ctrlKey) && e.key === 'l' && state.screen === 'main') {
    e.preventDefault();
    doLock();
  }
  // Cmd/Ctrl+F to search
  if ((e.metaKey || e.ctrlKey) && e.key === 'f' && state.screen === 'main') {
    e.preventDefault();
    const s = $('.search-input');
    if (s) { s.focus(); s.select(); }
  }
  // Cmd/Ctrl+A to select all (only when not editing an input)
  if ((e.metaKey || e.ctrlKey) && e.key === 'a' && state.screen === 'main') {
    if (['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;
    e.preventDefault();
    state.multiSelectMode = true;
    state.filteredEntries.forEach(item => state.selectedIds.add(item.id));
    render();
  }
  // F2 to rename selected file
  if (e.key === 'F2' && state.screen === 'main') {
    if (['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;
    if (state.selectedIds.size === 1 && !state.modalOpen) {
      e.preventDefault();
      const id = Array.from(state.selectedIds)[0];
      const entry = state.entries.find(x => x.id === id);
      if (entry) showRenameModal(entry);
    }
  }
  // Space to preview/open selected file (macOS Quick Look shortcut)
  if (e.key === ' ' && state.screen === 'main') {
    if (['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;
    if (state.selectedIds.size === 1) {
      e.preventDefault();
      const id = Array.from(state.selectedIds)[0];
      openEntry(id);
    }
  }
  // Delete / Backspace to delete selected
  if ((e.key === 'Delete' || e.key === 'Backspace') && state.screen === 'main') {
    if (['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) return;
    if (state.selectedIds.size > 0 && !state.modalOpen) {
      e.preventDefault();
      if (state.selectedIds.size === 1) {
        const id = Array.from(state.selectedIds)[0];
        const entry = state.entries.find(x => x.id === id);
        if (entry) deleteEntry(entry);
      } else {
        deleteSelected();
      }
    }
  }
});

init();
