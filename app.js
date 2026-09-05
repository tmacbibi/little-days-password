'use strict';

const $ = (id) => document.getElementById(id);
const STORAGE_KEY = 'ldp_vault_v1';
const SALT_KEY = 'ldp_salt_v1';
const SETTINGS_KEY = 'ldp_settings_v1';
const HIDDEN_LOCK_MS = 30_000;
const INACTIVITY_LOCK_MS = 180_000;

let vault = [];
let cryptoKey = null;
let activeFilter = 'all';
let editingId = null;
let hiddenAt = null;
let inactivityTimer = null;

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(bytes){ return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(str){ return Uint8Array.from(atob(str), c=>c.charCodeAt(0)); }
function randomBytes(n){ const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }

async function deriveKey(pin, salt){
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:250000, hash:'SHA-256'},
    base,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}

async function encryptVault(){
  if(!cryptoKey) throw new Error('LOCKED');
  const iv = randomBytes(12);
  const data = enc.encode(JSON.stringify(vault));
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, cryptoKey, data);
  localStorage.setItem(STORAGE_KEY, JSON.stringify({iv:b64(iv), data:b64(cipher)}));
}

async function decryptVault(key){
  const raw = localStorage.getItem(STORAGE_KEY);
  if(!raw) return [];
  const payload = JSON.parse(raw);
  const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(payload.iv)}, key, unb64(payload.data));
  return JSON.parse(dec.decode(plain));
}

function vaultExists(){ return !!localStorage.getItem(STORAGE_KEY) && !!localStorage.getItem(SALT_KEY); }

function show(el){ el.classList.remove('hidden'); }
function hide(el){ el.classList.add('hidden'); }
function escapeHtml(s=''){ return String(s).replace(/[&<>'"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }

function toast(msg){
  $('toast').textContent = msg; show($('toast'));
  clearTimeout(toast._t); toast._t = setTimeout(()=>hide($('toast')), 1800);
}

function renderLockMode(){
  show($('lockScreen')); hide($('mainScreen')); hide($('editorScreen')); hide($('settingsScreen'));
  if(vaultExists()){
    hide($('firstRunBlock')); show($('unlockBlock')); $('unlockPin').value='';
    setTimeout(()=>$('unlockPin').focus(),50);
  } else {
    show($('firstRunBlock')); hide($('unlockBlock'));
  }
}

async function createVault(){
  const pin = $('newPin').value.trim();
  const confirm = $('confirmPin').value.trim();
  if(!/^\d{6,12}$/.test(pin)){ toast('PIN 請使用 6～12 位數字'); return; }
  if(pin !== confirm){ toast('兩次 PIN 不一致'); return; }
  const salt = randomBytes(16);
  localStorage.setItem(SALT_KEY, b64(salt));
  cryptoKey = await deriveKey(pin, salt);
  vault = [];
  await encryptVault();
  $('newPin').value=''; $('confirmPin').value='';
  enterApp();
}

async function unlock(){
  const pin = $('unlockPin').value.trim();
  if(!pin) return;
  try{
    const salt = unb64(localStorage.getItem(SALT_KEY));
    const key = await deriveKey(pin, salt);
    const data = await decryptVault(key);
    cryptoKey = key; vault = Array.isArray(data) ? data : [];
    hide($('unlockError'));
    enterApp();
  }catch(err){
    show($('unlockError'));
    $('unlockPin').select();
  }
}

function enterApp(){
  hide($('lockScreen')); show($('mainScreen'));
  resetInactivityTimer();
  render();
}

function lockApp(){
  vault = [];
  cryptoKey = null;
  editingId = null;
  clearTimeout(inactivityTimer);
  renderLockMode();
}

function resetInactivityTimer(){
  if(!cryptoKey) return;
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(lockApp, INACTIVITY_LOCK_MS);
}

function fmtDate(iso){
  try{return new Intl.DateTimeFormat('zh-TW',{month:'numeric',day:'numeric'}).format(new Date(iso));}catch{return ''}
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
    .sort((a,b)=> Number(b.favorite)-Number(a.favorite) || new Date(b.updatedAt)-new Date(a.updatedAt));
}

function render(){
  if(!cryptoKey) return;
  const items = filteredItems();
  $('countLabel').textContent = `${vault.length} 筆`;
  $('list').innerHTML = '';
  hide($('emptyState'));
  if(items.length===0){
    show($('emptyState'));
    $('emptyState').querySelector('h2').textContent = vault.length ? '找不到符合的紀錄' : '還沒有任何紀錄';
    return;
  }
  for(const item of items){
    const div=document.createElement('article'); div.className='item'; div.dataset.id=item.id;
    div.innerHTML = `
      <div class="item-top">
        <div>
          <div class="item-title">${item.favorite?'<span class="star">⭐</span>':''}${escapeHtml(item.name)}</div>
          ${item.account?`<div class="account">${escapeHtml(item.account)}</div>`:''}
        </div>
        <span class="badge">${escapeHtml(item.category||'其他')}</span>
      </div>
      <div class="hint-row">
        <div class="hint" data-hint="${escapeHtml(item.hint)}" data-open="0">••••••••</div>
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
  $('hintInput').value = item?.hint || '';
  $('categoryInput').value = item?.category || '其他';
  $('favoriteInput').checked = !!item?.favorite;
  $('noteInput').value = item?.note || '';
  show($('editorScreen'));
  setTimeout(()=>$('nameInput').focus(),60);
}

function closeEditor(){ hide($('editorScreen')); editingId=null; }

async function saveItem(){
  const name=$('nameInput').value.trim();
  const hint=$('hintInput').value.trim();
  if(!name){ toast('請輸入名稱'); return; }
  if(!hint){ toast('請輸入密碼提示'); return; }
  const now=new Date().toISOString();
  const data={
    name,
    account:$('accountInput').value.trim(),
    hint,
    category:$('categoryInput').value,
    favorite:$('favoriteInput').checked,
    note:$('noteInput').value.trim(),
    updatedAt:now
  };
  if(editingId){
    const i=vault.findIndex(x=>x.id===editingId);
    if(i>=0) vault[i]={...vault[i],...data};
  }else{
    vault.push({id:crypto.randomUUID(),createdAt:now,...data});
  }
  await encryptVault();
  closeEditor(); render(); toast('已儲存');
}

async function deleteItem(id){
  const item=vault.find(x=>x.id===id); if(!item) return;
  if(!confirm(`刪除「${item.name}」？`)) return;
  vault=vault.filter(x=>x.id!==id); await encryptVault(); render(); toast('已刪除');
}

async function copyText(text,label='已複製'){
  try{ await navigator.clipboard.writeText(text); toast(label); }
  catch{ toast('無法存取剪貼簿'); }
}

async function changePin(){
  const current=prompt('請輸入目前 PIN'); if(current===null) return;
  try{
    const salt=unb64(localStorage.getItem(SALT_KEY));
    const currentKey=await deriveKey(current.trim(),salt);
    await decryptVault(currentKey);
  }catch{ toast('目前 PIN 不正確'); return; }
  const next=prompt('請輸入新的 6～12 位數字 PIN'); if(next===null) return;
  if(!/^\d{6,12}$/.test(next.trim())){ toast('新 PIN 格式不正確'); return; }
  const salt=randomBytes(16);
  const newKey=await deriveKey(next.trim(),salt);
  cryptoKey=newKey;
  localStorage.setItem(SALT_KEY,b64(salt));
  await encryptVault();
  toast('PIN 已變更');
}

async function wipe(){
  if(!confirm('確定要永久清除這支手機的所有紀錄？')) return;
  if(!confirm('最後確認：清除後無法復原。')) return;
  localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(SALT_KEY); localStorage.removeItem(SETTINGS_KEY);
  lockApp();
}

function bindEvents(){
  $('createVaultBtn').addEventListener('click',createVault);
  $('unlockBtn').addEventListener('click',unlock);
  $('unlockPin').addEventListener('keydown',e=>{if(e.key==='Enter') unlock();});
  $('confirmPin').addEventListener('keydown',e=>{if(e.key==='Enter') createVault();});
  $('addBtn').addEventListener('click',()=>openEditor());
  $('quickAddNav').addEventListener('click',()=>openEditor());
  $('cancelEditBtn').addEventListener('click',closeEditor);
  $('saveBtn').addEventListener('click',saveItem);
  $('settingsBtn').addEventListener('click',()=>show($('settingsScreen')));
  $('closeSettingsBtn').addEventListener('click',()=>hide($('settingsScreen')));
  $('lockNowBtn').addEventListener('click',lockApp);
  $('lockNav').addEventListener('click',lockApp);
  $('changePinBtn').addEventListener('click',changePin);
  $('wipeBtn').addEventListener('click',wipe);
  $('searchInput').addEventListener('input',render);

  $('filterBar').addEventListener('click',e=>{
    const btn=e.target.closest('.chip'); if(!btn)return;
    activeFilter=btn.dataset.filter;
    document.querySelectorAll('.chip').forEach(x=>x.classList.toggle('active',x===btn)); render();
  });

  $('list').addEventListener('click',e=>{
    const card=e.target.closest('.item'); if(!card)return;
    const item=vault.find(x=>x.id===card.dataset.id); if(!item)return;
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

  ['pointerdown','keydown','touchstart'].forEach(evt=>document.addEventListener(evt,resetInactivityTimer,{passive:true}));

  document.addEventListener('visibilitychange',()=>{
    if(document.hidden){ hiddenAt=Date.now(); }
    else if(hiddenAt && cryptoKey && Date.now()-hiddenAt > HIDDEN_LOCK_MS){ lockApp(); hiddenAt=null; }
    else hiddenAt=null;
  });

  window.addEventListener('pagehide',()=>{ if(cryptoKey) hiddenAt=Date.now(); });
}

async function init(){
  bindEvents();
  if('serviceWorker' in navigator){ try{ await navigator.serviceWorker.register('./sw.js'); }catch(e){ console.warn('SW unavailable',e); } }
  renderLockMode();
}

init();
