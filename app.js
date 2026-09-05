'use strict';

const $ = (id) => document.getElementById(id);

// v1.1 storage
const VAULT_KEY = 'ldp_vault_v2';
const FACE_KEY = 'ldp_face_v1';
const SETTINGS_KEY = 'ldp_settings_v2';

// legacy v1 storage (auto-migrated after first PIN unlock)
const LEGACY_STORAGE_KEY = 'ldp_vault_v1';
const LEGACY_SALT_KEY = 'ldp_salt_v1';
const LEGACY_SETTINGS_KEY = 'ldp_settings_v1';
const LEGACY_ARCHIVE_KEY = 'ldp_legacy_archive_v1';

const HIDDEN_LOCK_MS = 30_000;
const DEFAULT_INACTIVITY_LOCK_MS = 60_000;
const BACKUP_REMINDER_MS = 30 * 24 * 60 * 60 * 1000;
const PIN_ITERATIONS = 350_000;

let vault = [];
let masterKey = null;
let masterKeyBytes = null;
let activeFilter = 'all';
let editingId = null;
let hiddenAt = null;
let inactivityTimer = null;

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToB64(bytes){
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function b64ToBytes(str){
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}
function bytesToB64url(bytes){
  return bytesToB64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlToBytes(str){
  const padded = str.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((str.length + 3) % 4);
  return b64ToBytes(padded);
}
function randomBytes(n){
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

function show(el){ el.classList.remove('hidden'); }
function hide(el){ el.classList.add('hidden'); }
function escapeHtml(s=''){
  return String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
function toast(msg, ms=1800){
  $('toast').textContent = msg;
  show($('toast'));
  clearTimeout(toast._t);
  toast._t = setTimeout(() => hide($('toast')), ms);
}

function getSettings(){
  try{
    return {
      inactivityLockMs: DEFAULT_INACTIVITY_LOCK_MS,
      lastBackupAt: null,
      firstDataAt: null,
      ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}')
    };
  }catch{
    return {inactivityLockMs:DEFAULT_INACTIVITY_LOCK_MS,lastBackupAt:null,firstDataAt:null};
  }
}
function setSettings(patch){
  const next = {...getSettings(), ...patch};
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
  return next;
}

async function derivePinKek(pin, salt, iterations = PIN_ITERATIONS){
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations, hash:'SHA-256'},
    base,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function importMasterKey(rawBytes){
  return crypto.subtle.importKey('raw', rawBytes, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}

async function encryptWithKey(key, bytes){
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, bytes);
  return {iv:bytesToB64(iv), data:bytesToB64(cipher)};
}

async function decryptWithKey(key, payload){
  return crypto.subtle.decrypt(
    {name:'AES-GCM', iv:b64ToBytes(payload.iv)},
    key,
    b64ToBytes(payload.data)
  );
}

async function createPinWrap(pin, rawMasterKey){
  const salt = randomBytes(16);
  const kek = await derivePinKek(pin, salt, PIN_ITERATIONS);
  const wrapped = await encryptWithKey(kek, rawMasterKey);
  return {salt:bytesToB64(salt), iterations:PIN_ITERATIONS, ...wrapped};
}

async function unwrapMasterWithPin(pin, pinWrap){
  const salt = b64ToBytes(pinWrap.salt);
  const kek = await derivePinKek(pin, salt, pinWrap.iterations || PIN_ITERATIONS);
  const plain = await decryptWithKey(kek, pinWrap);
  return new Uint8Array(plain);
}

async function encryptVaultToPayload(){
  if(!masterKey) throw new Error('LOCKED');
  return encryptWithKey(masterKey, enc.encode(JSON.stringify(vault)));
}

async function persistVault(pinWrapOverride = null){
  if(!masterKey) throw new Error('LOCKED');
  const current = readVaultRecord();
  const record = {
    version: 2,
    createdAt: current?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    vault: await encryptVaultToPayload(),
    pin: pinWrapOverride || current?.pin
  };
  if(!record.pin) throw new Error('PIN_WRAP_MISSING');
  localStorage.setItem(VAULT_KEY, JSON.stringify(record));
}

function readVaultRecord(){
  try{
    const raw = localStorage.getItem(VAULT_KEY);
    return raw ? JSON.parse(raw) : null;
  }catch{ return null; }
}

async function decryptVaultRecord(key, record){
  const plain = await decryptWithKey(key, record.vault);
  const data = JSON.parse(dec.decode(plain));
  return Array.isArray(data) ? data : [];
}

function legacyVaultExists(){
  return !!localStorage.getItem(LEGACY_STORAGE_KEY) && !!localStorage.getItem(LEGACY_SALT_KEY);
}
function vaultExists(){
  return !!localStorage.getItem(VAULT_KEY) || legacyVaultExists();
}

async function decryptLegacyVault(pin){
  const salt = b64ToBytes(localStorage.getItem(LEGACY_SALT_KEY));
  const legacyKey = await derivePinKek(pin, salt, 250_000);
  const raw = JSON.parse(localStorage.getItem(LEGACY_STORAGE_KEY));
  const plain = await crypto.subtle.decrypt(
    {name:'AES-GCM', iv:b64ToBytes(raw.iv)},
    legacyKey,
    b64ToBytes(raw.data)
  );
  const data = JSON.parse(dec.decode(plain));
  return Array.isArray(data) ? data : [];
}

async function migrateLegacy(pin){
  const legacyData = await decryptLegacyVault(pin);
  const rawMaster = randomBytes(32);
  const key = await importMasterKey(rawMaster);
  masterKeyBytes = rawMaster;
  masterKey = key;
  vault = legacyData;
  const pinWrap = await createPinWrap(pin, rawMaster);
  const record = {
    version: 2,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    vault: await encryptVaultToPayload(),
    pin: pinWrap
  };
  localStorage.setItem(VAULT_KEY, JSON.stringify(record));

  // Preserve only non-sensitive legacy settings if present.
  try{
    const old = JSON.parse(localStorage.getItem(LEGACY_SETTINGS_KEY) || '{}');
    setSettings({
      inactivityLockMs: old.inactivityLockMs || DEFAULT_INACTIVITY_LOCK_MS,
      firstDataAt: legacyData.length ? new Date().toISOString() : null
    });
  }catch{}

  // v1.1.1 safety rule: NEVER delete legacy v1 automatically.
  // Keep an encrypted snapshot so a bad migration/update cannot destroy the only copy.
  try{
    localStorage.setItem(LEGACY_ARCHIVE_KEY, JSON.stringify({
      archivedAt:new Date().toISOString(),
      vault:localStorage.getItem(LEGACY_STORAGE_KEY),
      salt:localStorage.getItem(LEGACY_SALT_KEY),
      settings:localStorage.getItem(LEGACY_SETTINGS_KEY)
    }));
  }catch{}
  toast('舊版資料已升級；原始舊資料仍保留', 2600);
}


function isStandaloneMode(){
  return window.matchMedia?.('(display-mode: standalone)').matches || window.navigator.standalone === true;
}

function showSafariTransferWarning(){
  if(!isStandaloneMode() || vaultExists()) return;
  const el=$('safariTransferWarning');
  if(el) show(el);
}

function showLegacyHelp(){
  alert(
    '如果你曾經先在 Safari 網頁版新增資料，再把 App 加到主畫面，iPhone 會把兩邊的本機資料分開。\n\n' +
    '找回方法：\n1. 用 Safari 直接開同一個 GitHub Pages 網址（不要從桌面圖示進入）\n' +
    '2. 用舊 PIN 解鎖；若偵測到 V1 資料會自動安全升級\n' +
    '3. 到設定按「立即備份」，存到 iCloud Drive\n' +
    '4. 回到桌面版小日子密碼 → 設定 → 從備份還原\n\n' +
    '新版還原會採「合併」，不會把目前資料直接覆蓋。'
  );
}

function mergeVaultItems(currentItems, incomingItems){
  const out=[...currentItems];
  const seen=new Set(out.map(x => x.id || `${x.name}\u0000${x.account}\u0000${x.hint}`));
  for(const item of incomingItems){
    const key=item.id || `${item.name}\u0000${item.account}\u0000${item.hint}`;
    if(!seen.has(key)){
      out.push(item);
      seen.add(key);
    }
  }
  return out;
}

async function recoverLegacyIntoCurrent(){
  if(!legacyVaultExists()){
    showLegacyHelp();
    return;
  }
  if(!masterKey){ toast('請先解鎖目前的密碼本'); return; }
  const oldPin=prompt('請輸入 V1 舊版使用的 PIN');
  if(oldPin===null) return;
  try{
    const legacyData=await decryptLegacyVault(oldPin.trim());
    const before=vault.length;
    vault=mergeVaultItems(vault, legacyData);
    await persistVault();
    if(vault.length && !getSettings().firstDataAt) setSettings({firstDataAt:new Date().toISOString()});
    render();
    toast(`已找回 ${vault.length-before} 筆舊版資料`, 2800);
  }catch(err){
    console.warn(err);
    toast('找回失敗：舊 PIN 不正確或舊資料無法讀取', 2800);
  }
}

function clearSensitiveMemory(){
  if(masterKeyBytes){
    try{ masterKeyBytes.fill(0); }catch{}
  }
  masterKeyBytes = null;
  masterKey = null;
  vault = [];
}

function renderLockMode(){
  show($('lockScreen'));
  hide($('mainScreen'));
  hide($('editorScreen'));
  hide($('settingsScreen'));

  if($('safariTransferWarning')) hide($('safariTransferWarning'));
  if(vaultExists()){
    hide($('firstRunBlock'));
    show($('unlockBlock'));
    $('unlockPin').value='';
    $('unlockError').classList.add('hidden');
    $('migrationNote').classList.toggle('hidden', !legacyVaultExists());
    updateFaceUnlockVisibility();
    setTimeout(() => {
      if($('faceUnlockBtn').classList.contains('hidden')) $('unlockPin').focus();
    }, 50);
  }else{
    show($('firstRunBlock'));
    hide($('unlockBlock'));
    showSafariTransferWarning();
  }
}

async function createVault(){
  const pin = $('newPin').value.trim();
  const confirmPin = $('confirmPin').value.trim();
  if(!/^\d{6,12}$/.test(pin)){ toast('PIN 請使用 6～12 位數字'); return; }
  if(pin !== confirmPin){ toast('兩次 PIN 不一致'); return; }

  const rawMaster = randomBytes(32);
  masterKeyBytes = rawMaster;
  masterKey = await importMasterKey(rawMaster);
  vault = [];
  const pinWrap = await createPinWrap(pin, rawMaster);
  const record = {
    version:2,
    createdAt:new Date().toISOString(),
    updatedAt:new Date().toISOString(),
    vault:await encryptVaultToPayload(),
    pin:pinWrap
  };
  localStorage.setItem(VAULT_KEY, JSON.stringify(record));
  setSettings({inactivityLockMs:DEFAULT_INACTIVITY_LOCK_MS,lastBackupAt:null,firstDataAt:null});
  $('newPin').value='';
  $('confirmPin').value='';
  enterApp();
  toast('密碼本已建立，可到設定啟用 Face ID', 2600);
}

async function unlock(){
  const pin = $('unlockPin').value.trim();
  if(!pin) return;
  try{
    if(legacyVaultExists() && !localStorage.getItem(VAULT_KEY)){
      await migrateLegacy(pin);
    }else{
      const record = readVaultRecord();
      if(!record?.pin) throw new Error('INVALID_VAULT');
      const rawMaster = await unwrapMasterWithPin(pin, record.pin);
      const key = await importMasterKey(rawMaster);
      const data = await decryptVaultRecord(key, record);
      masterKeyBytes = rawMaster;
      masterKey = key;
      vault = data;
    }
    hide($('unlockError'));
    $('unlockPin').value='';
    enterApp();
  }catch(err){
    console.warn(err);
    show($('unlockError'));
    $('unlockPin').select();
  }
}

function enterApp(){
  try{ navigator.storage?.persist?.(); }catch{}
  hide($('lockScreen'));
  show($('mainScreen'));
  resetInactivityTimer();
  render();
  updateSettingsUI();
}

function lockApp(){
  clearSensitiveMemory();
  editingId = null;
  $('plainPasswordInput').value='';
  clearTimeout(inactivityTimer);
  renderLockMode();
}

function resetInactivityTimer(){
  if(!masterKey) return;
  clearTimeout(inactivityTimer);
  const ms = Number(getSettings().inactivityLockMs || DEFAULT_INACTIVITY_LOCK_MS);
  inactivityTimer = setTimeout(lockApp, ms);
}

function fmtDateTime(iso){
  if(!iso) return '尚未備份';
  try{
    return new Intl.DateTimeFormat('zh-TW',{
      year:'numeric',month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'
    }).format(new Date(iso));
  }catch{return '尚未備份';}
}

function filteredItems(){
  const q = $('searchInput').value.trim().toLowerCase();
  return [...vault]
    .filter(item => {
      if(activeFilter==='favorite' && !item.favorite) return false;
      if(!['all','favorite'].includes(activeFilter) && item.category!==activeFilter) return false;
      if(!q) return true;
      return [item.name,item.account,item.category,item.note].join(' ').toLowerCase().includes(q);
    })
    .sort((a,b) => Number(b.favorite)-Number(a.favorite) || new Date(b.updatedAt)-new Date(a.updatedAt));
}

function backupReminderDue(){
  const s = getSettings();
  const anchor = s.lastBackupAt || s.firstDataAt;
  if(!anchor || !vault.length) return false;
  return Date.now() - new Date(anchor).getTime() >= BACKUP_REMINDER_MS;
}

function renderBackupReminder(){
  const due = backupReminderDue();
  $('backupReminder').classList.toggle('hidden', !due);
  if(!due) return;
  const s = getSettings();
  $('backupReminderText').textContent = s.lastBackupAt
    ? '距離上次備份已超過 30 天。'
    : '已有資料超過 30 天尚未備份。';
}

function render(){
  if(!masterKey) return;
  const items = filteredItems();
  $('countLabel').textContent = `${vault.length} 筆`;
  $('list').innerHTML = '';
  hide($('emptyState'));
  renderBackupReminder();
  if(items.length===0){
    show($('emptyState'));
    $('emptyState').querySelector('h2').textContent = vault.length ? '找不到符合的紀錄' : '還沒有任何紀錄';
    return;
  }

  for(const item of items){
    const div = document.createElement('article');
    div.className='item';
    div.dataset.id=item.id;
    div.innerHTML = `
      <div class="item-top">
        <div>
          <div class="item-title">${item.favorite?'<span class="star">⭐</span>':''}${escapeHtml(item.name)}</div>
          ${item.account?`<div class="account">${escapeHtml(item.account)}</div>`:''}
        </div>
        <span class="badge">${escapeHtml(item.category||'其他')}</span>
      </div>
      <div class="hint-row">
        <div class="hint" data-open="0">••••••••</div>
        <button class="mini-btn revealBtn">查看</button>
        <button class="mini-btn copyHintBtn">複製</button>
      </div>
      <div class="item-actions">
        ${item.account?'<button class="mini-btn copyAccountBtn">複製帳號</button>':''}
        <button class="mini-btn editBtn">編輯</button>
        <button class="mini-btn delete-mini deleteBtn">刪除</button>
      </div>`;
    $('list').appendChild(div);
  }
}

function openEditor(item=null){
  editingId = item?.id || null;
  $('editorTitle').textContent = item ? '編輯密碼提示' : '新增密碼提示';
  $('nameInput').value = item?.name || '';
  $('accountInput').value = item?.account || '';
  $('plainPasswordInput').value = '';
  $('hintInput').value = item?.hint || '';
  $('categoryInput').value = item?.category || '其他';
  $('favoriteInput').checked = !!item?.favorite;
  $('noteInput').value = item?.note || '';
  $('maskResultNote').textContent = '';
  hide($('maskResultNote'));
  show($('editorScreen'));
  setTimeout(() => $('nameInput').focus(), 60);
}

function closeEditor(){
  $('plainPasswordInput').value='';
  hide($('editorScreen'));
  editingId=null;
}

function randomMaskCount(candidateCount){
  if(candidateCount >= 6) return Math.min(candidateCount - 2, Math.random() < 0.5 ? 3 : 4);
  if(candidateCount >= 4) return 2;
  if(candidateCount >= 2) return 1;
  return 0;
}

function createMaskedHint(plain){
  const chars = Array.from(plain);
  const candidates = [];
  chars.forEach((ch, i) => {
    if(/[A-Za-z0-9]/.test(ch)) candidates.push(i);
  });
  const count = randomMaskCount(candidates.length);
  if(count === 0) return {hint:'', count:0};

  // Fisher-Yates shuffle using cryptographically secure random values.
  const pool = [...candidates];
  for(let i=pool.length-1;i>0;i--){
    const r = new Uint32Array(1);
    crypto.getRandomValues(r);
    const j = r[0] % (i+1);
    [pool[i],pool[j]] = [pool[j],pool[i]];
  }
  const selected = new Set(pool.slice(0, count));
  return {
    hint: chars.map((ch,i) => selected.has(i) ? '*' : ch).join(''),
    count
  };
}

function generateHintFromPlain(){
  const input = $('plainPasswordInput');
  const plain = input.value;
  if(!plain){ toast('請先輸入真正密碼'); return; }

  const {hint,count} = createMaskedHint(plain);
  // Best-effort: immediately remove the plaintext from the DOM after local transformation.
  input.value = '';
  if(!hint){
    toast('至少需要 2 個英文字母或數字才能自動遮碼');
    return;
  }
  $('hintInput').value = hint;
  $('maskResultNote').textContent = `已隨機遮住 ${count} 碼；真正密碼輸入框已清空。`;
  show($('maskResultNote'));
}

async function saveItem(){
  const name = $('nameInput').value.trim();
  const hint = $('hintInput').value.trim();
  if(!name){ toast('請輸入名稱'); return; }
  if(!hint){ toast('請輸入密碼提示'); return; }

  const now = new Date().toISOString();
  const data = {
    name,
    account:$('accountInput').value.trim(),
    hint,
    category:$('categoryInput').value,
    favorite:$('favoriteInput').checked,
    note:$('noteInput').value.trim(),
    updatedAt:now
  };

  if(editingId){
    const i=vault.findIndex(x => x.id===editingId);
    if(i>=0) vault[i]={...vault[i],...data};
  }else{
    vault.push({id:crypto.randomUUID(),createdAt:now,...data});
    const s = getSettings();
    if(!s.firstDataAt) setSettings({firstDataAt:now});
  }
  await persistVault();
  closeEditor();
  render();
  updateSettingsUI();
  toast('已儲存');
}

async function deleteItem(id){
  const item=vault.find(x=>x.id===id);
  if(!item) return;
  if(!confirm(`刪除「${item.name}」？`)) return;
  vault=vault.filter(x=>x.id!==id);
  await persistVault();
  render();
  toast('已刪除');
}

async function copyText(text,label='已複製'){
  try{
    await navigator.clipboard.writeText(text);
    toast(label);
  }catch{
    toast('無法存取剪貼簿');
  }
}

async function changePin(){
  if(!masterKeyBytes){ toast('請先解鎖'); return; }
  const current = prompt('請輸入目前 PIN');
  if(current===null) return;
  try{
    const record = readVaultRecord();
    await unwrapMasterWithPin(current.trim(), record.pin);
  }catch{
    toast('目前 PIN 不正確');
    return;
  }

  const next = prompt('請輸入新的 6～12 位數字 PIN');
  if(next===null) return;
  if(!/^\d{6,12}$/.test(next.trim())){ toast('新 PIN 格式不正確'); return; }

  const newWrap = await createPinWrap(next.trim(), masterKeyBytes);
  await persistVault(newWrap);
  toast('PIN 已變更');
}

function webAuthnSupported(){
  return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
}

function readFaceConfig(){
  try{
    const raw = localStorage.getItem(FACE_KEY);
    return raw ? JSON.parse(raw) : null;
  }catch{ return null; }
}

async function getPrfResult(credentialId, prfSalt){
  const assertion = await navigator.credentials.get({
    publicKey:{
      challenge: randomBytes(32),
      allowCredentials:[{
        id:b64urlToBytes(credentialId),
        type:'public-key',
        transports:['internal']
      }],
      userVerification:'required',
      timeout:60_000,
      extensions:{prf:{eval:{first:prfSalt}}}
    }
  });
  if(!assertion) throw new Error('FACE_CANCELLED');
  const ext = assertion.getClientExtensionResults?.();
  const result = ext?.prf?.results?.first;
  if(!result) throw new Error('PRF_UNAVAILABLE');
  return new Uint8Array(result);
}

async function faceKekFromPrf(prfBytes){
  return crypto.subtle.importKey('raw', prfBytes, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}

async function enableFaceId(){
  if(!webAuthnSupported()){
    toast('這個環境無法使用 Face ID / Passkey');
    return;
  }
  if(!masterKeyBytes){ toast('請先解鎖'); return; }

  try{
    const prfSalt = randomBytes(32);
    const credential = await navigator.credentials.create({
      publicKey:{
        challenge:randomBytes(32),
        rp:{name:'小日子密碼'},
        user:{
          id:randomBytes(16),
          name:'little-days-local-user',
          displayName:'小日子密碼'
        },
        pubKeyCredParams:[
          {type:'public-key',alg:-7},
          {type:'public-key',alg:-257}
        ],
        authenticatorSelection:{
          authenticatorAttachment:'platform',
          residentKey:'preferred',
          userVerification:'required'
        },
        attestation:'none',
        timeout:60_000,
        extensions:{prf:{eval:{first:prfSalt}}}
      }
    });
    if(!credential) throw new Error('FACE_CANCELLED');

    const credentialId = bytesToB64url(new Uint8Array(credential.rawId));
    let prfResult = credential.getClientExtensionResults?.()?.prf?.results?.first;
    let prfBytes = prfResult ? new Uint8Array(prfResult) : null;

    // Some implementations only return PRF output during assertion.
    if(!prfBytes){
      prfBytes = await getPrfResult(credentialId, prfSalt);
    }

    const faceKek = await faceKekFromPrf(prfBytes);
    const wrapped = await encryptWithKey(faceKek, masterKeyBytes);
    localStorage.setItem(FACE_KEY, JSON.stringify({
      version:1,
      credentialId,
      prfSalt:bytesToB64url(prfSalt),
      wrappedMasterKey:wrapped,
      createdAt:new Date().toISOString()
    }));
    updateSettingsUI();
    updateFaceUnlockVisibility();
    toast('Face ID 已啟用', 2200);
  }catch(err){
    console.warn('Face ID enable failed', err);
    if(String(err?.name||'').includes('NotAllowed')) toast('已取消 Face ID 設定');
    else if(String(err?.message||'').includes('PRF')) toast('此裝置的 Face ID 加密功能暫不支援');
    else toast('Face ID 設定失敗，仍可繼續使用 PIN');
  }
}

async function faceUnlock(){
  const cfg = readFaceConfig();
  if(!cfg || !webAuthnSupported()) return;
  try{
    const prfSalt = b64urlToBytes(cfg.prfSalt);
    const prfBytes = await getPrfResult(cfg.credentialId, prfSalt);
    const faceKek = await faceKekFromPrf(prfBytes);
    const rawMaster = new Uint8Array(await decryptWithKey(faceKek, cfg.wrappedMasterKey));
    const key = await importMasterKey(rawMaster);
    const record = readVaultRecord();
    const data = await decryptVaultRecord(key, record);
    masterKeyBytes = rawMaster;
    masterKey = key;
    vault = data;
    enterApp();
  }catch(err){
    console.warn('Face ID unlock failed', err);
    if(String(err?.name||'').includes('NotAllowed')) toast('Face ID 已取消');
    else toast('Face ID 解鎖失敗，請改用 PIN');
  }
}

function disableFaceId(showToast=true){
  localStorage.removeItem(FACE_KEY);
  updateFaceUnlockVisibility();
  updateSettingsUI();
  if(showToast) toast('Face ID 已停用');
}

function updateFaceUnlockVisibility(){
  const visible = !!readFaceConfig() && webAuthnSupported() && !!localStorage.getItem(VAULT_KEY);
  $('faceUnlockBtn').classList.toggle('hidden', !visible);
  $('faceDivider').classList.toggle('hidden', !visible);
}

function updateSettingsUI(){
  const face = readFaceConfig();
  const faceAvailable = webAuthnSupported();
  if(face){
    $('faceStatusText').textContent = '已啟用。下次開啟 App 可直接使用 Face ID 解鎖。';
    hide($('enableFaceBtn'));
    show($('disableFaceBtn'));
  }else{
    $('faceStatusText').textContent = faceAvailable
      ? '尚未設定。啟用後可直接用 Face ID 解鎖，PIN 仍保留作為備援。'
      : '目前這個瀏覽環境不支援 Face ID / Passkey。請使用 Safari 或加入主畫面後再試。';
    $('enableFaceBtn').disabled = !faceAvailable;
    show($('enableFaceBtn'));
    hide($('disableFaceBtn'));
  }

  const s = getSettings();
  $('autoLockSelect').value = String(s.inactivityLockMs || DEFAULT_INACTIVITY_LOCK_MS);
  $('lastBackupLabel').textContent = fmtDateTime(s.lastBackupAt);
}

async function createBackupFile(){
  const recordRaw = localStorage.getItem(VAULT_KEY);
  if(!recordRaw) throw new Error('NO_VAULT');
  const settings = getSettings();
  const safeSettings = {
    firstDataAt: settings.firstDataAt || null
  };
  const backup = {
    format:'little-days-password-backup',
    version:2,
    createdAt:new Date().toISOString(),
    vault:JSON.parse(recordRaw),
    settings:safeSettings
  };
  const text = JSON.stringify(backup);
  const stamp = new Date().toISOString().replace(/[:T]/g,'-').slice(0,16);
  const name = `小日子密碼_${stamp}.ldpbackup`;
  return new File([text], name, {type:'application/json'});
}

async function backupNow(){
  try{
    const file = await createBackupFile();
    if(navigator.share && navigator.canShare?.({files:[file]})){
      await navigator.share({
        files:[file],
        title:'小日子密碼加密備份',
        text:'請選「儲存到檔案」，再存到 iCloud Drive。'
      });
      const now = new Date().toISOString();
      setSettings({lastBackupAt:now});
      updateSettingsUI();
      renderBackupReminder();
      toast('備份檔已產生');
    }else{
      const url = URL.createObjectURL(file);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      const now = new Date().toISOString();
      setSettings({lastBackupAt:now});
      updateSettingsUI();
      renderBackupReminder();
      toast('備份檔已下載');
    }
  }catch(err){
    if(err?.name === 'AbortError') return;
    console.warn(err);
    toast('備份失敗，請再試一次');
  }
}

async function restoreBackupFile(file){
  if(!file) return;
  try{
    const backup = JSON.parse(await file.text());
    if(backup?.format !== 'little-days-password-backup' || backup?.version !== 2 || !backup?.vault?.pin || !backup?.vault?.vault){
      throw new Error('INVALID_BACKUP');
    }
    const pin = prompt('請輸入這份備份的 App PIN 以驗證資料');
    if(pin===null) return;
    const incomingRawMaster = await unwrapMasterWithPin(pin.trim(), backup.vault.pin);
    const incomingKey = await importMasterKey(incomingRawMaster);
    const incomingData = await decryptVaultRecord(incomingKey, backup.vault);
    if(!Array.isArray(incomingData)) throw new Error('INVALID_DATA');

    // Safety-first restore: merge by default so an old backup can never silently wipe newer local data.
    if(masterKey){
      const before=vault.length;
      vault=mergeVaultItems(vault, incomingData);
      await persistVault();
      setSettings({
        lastBackupAt:new Date().toISOString(),
        firstDataAt:getSettings().firstDataAt || backup.settings?.firstDataAt || (vault.length ? new Date().toISOString() : null)
      });
      hide($('settingsScreen'));
      render();
      toast(`備份已合併，新增 ${vault.length-before} 筆`, 2800);
    }else{
      // First-run/import case: adopt the backup vault as-is.
      localStorage.setItem(VAULT_KEY, JSON.stringify(backup.vault));
      disableFaceId(false);
      setSettings({
        inactivityLockMs:DEFAULT_INACTIVITY_LOCK_MS,
        lastBackupAt:new Date().toISOString(),
        firstDataAt:backup.settings?.firstDataAt || (incomingData.length ? new Date().toISOString() : null)
      });
      masterKeyBytes=incomingRawMaster;
      masterKey=incomingKey;
      vault=incomingData;
      enterApp();
      toast('備份已還原；請重新啟用 Face ID', 2800);
    }
  }catch(err){
    console.warn(err);
    toast('無法還原：檔案或 PIN 不正確', 2600);
  }finally{
    $('restoreFileInput').value='';
  }
}

async function wipe(){
  if(!confirm('確定要永久清除這支手機的所有紀錄？')) return;
  if(!confirm('最後確認：清除後只能靠先前的備份還原。')) return;
  [VAULT_KEY,FACE_KEY,SETTINGS_KEY].forEach(k => localStorage.removeItem(k));
  lockApp();
}

function bindEvents(){
  $('createVaultBtn').addEventListener('click',createVault);
  $('legacyHelpBtn')?.addEventListener('click',showLegacyHelp);
  $('unlockBtn').addEventListener('click',unlock);
  $('faceUnlockBtn').addEventListener('click',faceUnlock);
  $('unlockPin').addEventListener('keydown',e => {if(e.key==='Enter') unlock();});
  $('confirmPin').addEventListener('keydown',e => {if(e.key==='Enter') createVault();});

  $('addBtn').addEventListener('click',() => openEditor());
  $('quickAddNav').addEventListener('click',() => openEditor());
  $('cancelEditBtn').addEventListener('click',closeEditor);
  $('saveBtn').addEventListener('click',saveItem);
  $('generateHintBtn').addEventListener('click',generateHintFromPlain);
  $('plainPasswordInput').addEventListener('keydown',e => {
    if(e.key==='Enter'){
      e.preventDefault();
      generateHintFromPlain();
    }
  });

  $('settingsBtn').addEventListener('click',() => { updateSettingsUI(); show($('settingsScreen')); });
  $('closeSettingsBtn').addEventListener('click',() => hide($('settingsScreen')));
  $('lockNowBtn').addEventListener('click',lockApp);
  $('lockNav').addEventListener('click',lockApp);
  $('changePinBtn').addEventListener('click',changePin);
  $('enableFaceBtn').addEventListener('click',enableFaceId);
  $('disableFaceBtn').addEventListener('click',() => disableFaceId(true));
  $('backupNowBtn').addEventListener('click',backupNow);
  $('recoverLegacyBtn')?.addEventListener('click',recoverLegacyIntoCurrent);
  $('backupNowTopBtn').addEventListener('click',backupNow);
  $('restoreBackupBtn').addEventListener('click',() => $('restoreFileInput').click());
  $('restoreFileInput').addEventListener('change',e => restoreBackupFile(e.target.files?.[0]));
  $('wipeBtn').addEventListener('click',wipe);
  $('searchInput').addEventListener('input',render);
  $('autoLockSelect').addEventListener('change',e => {
    setSettings({inactivityLockMs:Number(e.target.value)});
    resetInactivityTimer();
    toast('自動鎖定時間已更新');
  });

  $('filterBar').addEventListener('click',e => {
    const btn=e.target.closest('.chip');
    if(!btn) return;
    activeFilter=btn.dataset.filter;
    document.querySelectorAll('.chip').forEach(x => x.classList.toggle('active',x===btn));
    render();
  });

  $('list').addEventListener('click',e => {
    const card=e.target.closest('.item');
    if(!card) return;
    const item=vault.find(x => x.id===card.dataset.id);
    if(!item) return;
    if(e.target.closest('.revealBtn')){
      const hintEl=card.querySelector('.hint');
      const open=hintEl.dataset.open==='1';
      hintEl.textContent=open?'••••••••':item.hint;
      hintEl.dataset.open=open?'0':'1';
      e.target.textContent=open?'查看':'隱藏';
    }else if(e.target.closest('.copyHintBtn')) copyText(item.hint,'提示已複製');
    else if(e.target.closest('.copyAccountBtn')) copyText(item.account,'帳號已複製');
    else if(e.target.closest('.editBtn')) openEditor(item);
    else if(e.target.closest('.deleteBtn')) deleteItem(item.id);
  });

  ['pointerdown','keydown','touchstart'].forEach(evt =>
    document.addEventListener(evt,resetInactivityTimer,{passive:true})
  );

  document.addEventListener('visibilitychange',() => {
    if(document.hidden){
      $('plainPasswordInput').value='';
      hiddenAt=Date.now();
    }else if(hiddenAt && masterKey && Date.now()-hiddenAt > HIDDEN_LOCK_MS){
      lockApp();
      hiddenAt=null;
    }else{
      hiddenAt=null;
    }
  });

  window.addEventListener('pagehide',() => {
    $('plainPasswordInput').value='';
    if(masterKey) hiddenAt=Date.now();
  });
}

async function init(){
  bindEvents();
  if('serviceWorker' in navigator){
    try{ await navigator.serviceWorker.register('./sw.js'); }
    catch(e){ console.warn('SW unavailable',e); }
  }
  renderLockMode();
  updateSettingsUI();
}

init();
