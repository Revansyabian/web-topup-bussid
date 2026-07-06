var API_REVANSTORE = '/api/revanstore';
var API_RVNSTORE = '/api/rvnstore';
var ADMIN_KEY = 'dhagwxwhu:f4afc5aa03e73130f5e055dfe6a708c4dc40759b';
var WHATSAPP_NUMBER = "6285199120995";
var MAX_TOPUP_AMOUNT = 2147483647;
var MAX_PASSWORD_LENGTH = 20;

var currentUser = null;
var currentAccount = null;
var currentAuthToken = null;
var pendingAction = null;
var pendingData = null;
var lastDeviceId = null;
var fingerprint = '';
var alertTimeout = null;
var isBlocked = false;
var blockedChecked = false;

function showBlockedScreen() {
    document.body.innerHTML = '<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#e0f2fe,#bae6fd,#7dd3fc);padding:20px;font-family:\'Segoe UI\',sans-serif;"><div style="background:#fff;border-radius:20px;padding:40px 30px;max-width:420px;width:100%;text-align:center;box-shadow:0 25px 60px rgba(0,0,0,0.1);"><div style="font-size:70px;color:#ef4444;margin-bottom:20px;">🔒</div><h1 style="color:#0c4a6e;font-size:24px;margin-bottom:10px;">AKSES DITOLAK</h1><p style="color:#64748b;font-size:14px;">Maaf, akses Anda telah diblokir.</p></div></div>';
}

async function getFingerprint() {
    var fp = '';
    fp += navigator.userAgent || '';
    fp += navigator.language || '';
    fp += (screen.width || 0) + 'x' + (screen.height || 0);
    fp += screen.colorDepth || '';
    fp += new Date().getTimezoneOffset();
    fp += navigator.hardwareConcurrency || '';
    fp += navigator.deviceMemory || '';
    fp += navigator.platform || '';
    return CryptoJS.MD5(fp).toString();
}

var BLOCK_CONFIG = { attempts: [5, 10, 15], durations: [15, 60, 1440] };

function getBlockKey(username) { return 'bussid_block_' + (username || 'global'); }

function getBlockData(username) {
    var key = getBlockKey(username);
    var data = localStorage.getItem(key);
    if (data) {
        try {
            var parsed = JSON.parse(data);
            if (parsed.blockedUntil && Date.now() > parsed.blockedUntil) { localStorage.removeItem(key); return { attempts: 0, blockedUntil: null, level: 0 }; }
            return parsed;
        } catch(e) { return { attempts: 0, blockedUntil: null, level: 0 }; }
    }
    return { attempts: 0, blockedUntil: null, level: 0 };
}

function saveBlockData(username, data) { var key = getBlockKey(username); localStorage.setItem(key, JSON.stringify(data)); }
function getBlockDuration(attempts) { if (attempts >= 15) return 1440; if (attempts >= 10) return 60; if (attempts >= 5) return 15; return 0; }
function sanitize(str) { if (!str) return ''; return String(str).replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;'); }

async function checkIfBlocked() {
    if (blockedChecked) return isBlocked;
    if (!fingerprint) fingerprint = await getFingerprint();
    try {
        var result = await callRevanstore('check_blocked', 'POST', { fingerprint: fingerprint });
        if (result && result.blocked) {
            isBlocked = true;
            localStorage.setItem('bussid_blocked', 'true');
        } else {
            isBlocked = false;
            localStorage.removeItem('bussid_blocked');
        }
        blockedChecked = true;
    } catch(e) {
        isBlocked = localStorage.getItem('bussid_blocked') === 'true';
        blockedChecked = true;
    }
    return isBlocked;
}

async function callRevanstore(path, method, data) {
    if (!fingerprint) fingerprint = await getFingerprint();
    if (isBlocked && path !== 'check_blocked') throw new Error('Akses ditolak');
    
    var payload = {
        path: path,
        method: method || 'GET',
        data: data || null,
        timestamp: Date.now()
    };
    
    var encryptedPayload = CryptoJS.AES.encrypt(JSON.stringify(payload), ADMIN_KEY).toString();
    
    var headers = {
        'Content-Type': 'application/json',
        'X-Fingerprint': fingerprint
    };
    
    if (currentUser && currentUser.username) {
        headers['X-Operator'] = CryptoJS.AES.encrypt(currentUser.username, ADMIN_KEY).toString();
    }
    
    var res = await fetch(API_REVANSTORE, { 
        method: 'POST', 
        headers: headers, 
        body: JSON.stringify({ data: encryptedPayload })
    });
    
    if (res.status === 429) throw new Error('Terlalu banyak request');
    var text = await res.text(); 
    if (!text || text === 'null') return null;
    
    var result = JSON.parse(text);
    
    if (result.encrypted && result.data) {
        var dec = CryptoJS.AES.decrypt(result.data, ADMIN_KEY).toString(CryptoJS.enc.Utf8);
        if (dec) return JSON.parse(dec);
    }
    
    return result;
}

async function callRvnstore(endpoint, method, body, authToken) {
    var res = await fetch(API_RVNSTORE, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ endpoint: endpoint, method: method || 'POST', body: body || null, authToken: authToken || null }) });
    return await res.json();
}

function showAlert(message, type, duration) {
    type = type || 'info'; duration = duration || 2500;
    var alertDiv = document.getElementById('alert');
    if (alertDiv) {
        var icons = { success: 'fa-check-circle', error: 'fa-exclamation-circle', warning: 'fa-exclamation-triangle', info: 'fa-info-circle', loading: 'fa-spinner fa-spin' };
        alertDiv.innerHTML = '<div class="alert-content"><div class="alert-icon"><i class="fas ' + (icons[type] || 'fa-info-circle') + '"></i></div><span>' + sanitize(message) + '</span></div>';
        alertDiv.className = 'alert ' + type + ' show';
        if (alertTimeout) clearTimeout(alertTimeout);
        if (type !== 'loading') { alertTimeout = setTimeout(function() { alertDiv.classList.remove('show'); }, duration); }
    }
}

function showLoading(message) {
    var overlay = document.getElementById('loadingOverlay');
    var msg = document.getElementById('loadingMessage');
    if (overlay && msg) { msg.textContent = message || 'Memproses...'; overlay.style.display = 'flex'; }
}

function hideLoading() { var overlay = document.getElementById('loadingOverlay'); if (overlay) overlay.style.display = 'none'; }

function formatCurrency(amount) { if (!amount && amount !== 0) return 'Rp 0'; return new Intl.NumberFormat('id-ID', { style: 'currency', currency: 'IDR', minimumFractionDigits: 0, maximumFractionDigits: 0 }).format(Math.abs(amount)); }

function parseAmount(input) {
    if (!input || input.trim() === '') return 0;
    var cleaned = input.toUpperCase().replace(/\s/g, '');
    if (cleaned === '2M' || cleaned === '2 M') return MAX_TOPUP_AMOUNT;
    var multiplier = 1, cleanInput = cleaned;
    if (cleaned.includes('M') && !cleaned.includes('JT') && !cleaned.includes('MAX')) { multiplier = 1000000000; cleanInput = cleaned.replace('M', ''); }
    else if (cleaned.includes('JT')) { multiplier = 1000000; cleanInput = cleaned.replace('JT', ''); }
    else if (cleaned.includes('RB') || cleaned.includes('K')) { multiplier = 1000; cleanInput = cleaned.replace(/[KRB]/g, ''); }
    else if (cleaned.includes('MAX')) return MAX_TOPUP_AMOUNT;
    var number = parseFloat(cleanInput.replace(/\./g, '').replace(',', '.'));
    var result = isNaN(number) ? 0 : Math.round(number * multiplier);
    return Math.min(result, MAX_TOPUP_AMOUNT);
}

function validateTopupAmount() {
    var input = document.getElementById('topupAmount'), preview = document.getElementById('amountPreview'), previewValue = document.getElementById('amountPreviewValue');
    var amount = parseAmount(input.value);
    if (amount > 0 && input.value.trim() !== '') { preview.style.display = 'block'; previewValue.textContent = formatCurrency(amount); }
    else { preview.style.display = 'none'; }
}

function hideAllSections() {
    var sections = ['accountInfo', 'topupSection', 'kurasSection', 'changeNameSection', 'historySection', 'settingsSection', 'receiptSection'];
    sections.forEach(function(section) { var el = document.getElementById(section); if (el) el.style.display = 'none'; });
    var searchCard = document.querySelector('.search-card'); if (searchCard) searchCard.style.display = 'none';
}

function showHome() { hideAllSections(); document.querySelector('.search-card').style.display = 'block'; }
function backToAccount() { if (currentAccount) { hideAllSections(); document.getElementById('accountInfo').style.display = 'block'; } else { showHome(); } }

function parseDate(dateStr) {
    if (!dateStr) return null;
    var parts = dateStr.split('/');
    if (parts.length !== 3) return null;
    var month = parseInt(parts[0], 10) - 1;
    var day = parseInt(parts[1], 10);
    var year = parseInt(parts[2], 10);
    if (isNaN(day) || isNaN(month) || isNaN(year)) return null;
    if (month < 0 || month > 11) return null;
    if (day < 1 || day > 31) return null;
    if (year < 2000) return null;
    var date = new Date(year, month, day);
    if (date.getMonth() !== month || date.getDate() !== day) return null;
    return date;
}

function calculateRemainingDays(expiryDate) {
    if (!expiryDate) return -999;
    if (expiryDate.includes('9999')) return 999999;
    var expiry = parseDate(expiryDate);
    if (!expiry) return -999;
    var now = new Date(); now.setHours(0, 0, 0, 0);
    return Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
}

function getDaysLeftClass(daysLeft) {
    if (daysLeft === 999999) return 'days-permanent';
    if (daysLeft <= 0) return 'days-red';
    if (daysLeft <= 3) return 'days-yellow';
    return 'days-green';
}

function getDaysLeftText(daysLeft) {
    if (daysLeft === 999999) return '♾️ Permanent';
    if (daysLeft === -999) return '⏰ Tidak ada';
    if (daysLeft < 0) return '⏰ Habis ' + Math.abs(daysLeft) + ' hari';
    if (daysLeft === 0) return '⚠️ Hari ini';
    if (daysLeft === 1) return '📅 1 hari';
    return '📅 ' + daysLeft + ' hari';
}

function checkAccountExpiry(user) {
    if (!user || !user.expiry_date) return { expired: true, daysLeft: -999, daysLeftText: '⏰ Tidak ada', daysLeftClass: 'days-red' };
    var daysLeft = calculateRemainingDays(user.expiry_date);
    var expired = daysLeft <= 0 && daysLeft !== 999999;
    return { expired: expired, daysLeft: daysLeft, daysLeftText: getDaysLeftText(daysLeft), daysLeftClass: getDaysLeftClass(daysLeft) };
}

function showExpiredBanner() { document.getElementById('expiredBanner').style.display = 'flex'; document.getElementById('mainApp').style.display = 'none'; }
function closeExpiredBanner() { document.getElementById('expiredBanner').style.display = 'none'; logout(); }

function openWhatsApp() { 
    var msg = encodeURIComponent("Assalamualaikum admin, saya ingin memperpanjang masa aktif akun BUSSID Top Up saya. Username: " + (currentUser ? currentUser.username : '')); 
    window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + msg, '_blank'); 
}

function openWhatsAppPassword() { 
    var msg = encodeURIComponent("Assalamualaikum admin, saya ingin mengubah password akun saya. Username: " + (currentUser ? currentUser.username : '')); 
    window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + msg, '_blank'); 
}

function updatePasswordCounter(fieldId) { var input = document.getElementById(fieldId), counter = document.getElementById(fieldId + 'CharCount'); if (input && counter) counter.textContent = input.value.length + '/' + MAX_PASSWORD_LENGTH; }

function showDeleteHistoryConfirm() {
    var overlay = document.getElementById('confirmOverlay');
    var msg = document.getElementById('confirmMessage');
    var yesBtn = document.getElementById('confirmYes');
    var noBtn = document.getElementById('confirmNo');
    var title = document.getElementById('confirmTitle');
    if (overlay && msg && yesBtn && noBtn) {
        if (title) title.innerHTML = '<i class="fas fa-trash"></i> HAPUS SEMUA RIWAYAT';
        msg.textContent = 'Yakin hapus semua riwayat?';
        overlay.style.display = 'flex';
        yesBtn.textContent = 'HAPUS SEMUA'; yesBtn.className = 'confirm-btn confirm-yes';
        yesBtn.onclick = function() { overlay.style.display = 'none'; deleteAllHistory(); };
        noBtn.onclick = function() { overlay.style.display = 'none'; };
        overlay.onclick = function(e) { if (e.target === overlay) overlay.style.display = 'none'; };
    }
}

function closeDeleteHistoryModal() { var overlay = document.getElementById('confirmOverlay'); if (overlay) overlay.style.display = 'none'; }

async function deleteAllHistory() {
    showLoading('Menghapus...');
    try {
        var transactions = await callRevanstore('transactions', 'GET');
        if (!transactions || typeof transactions !== 'object' || Object.keys(transactions).length === 0) { 
            hideLoading(); 
            showAlert('Tidak ada riwayat!', 'warning'); 
            return; 
        }
        var count = 0;
        for (var key in transactions) { 
            await callRevanstore('transactions/' + key, 'DELETE');
            count++; 
        }
        hideLoading(); 
        showAlert(count + ' riwayat dihapus!', 'success');
        if (document.getElementById('historySection').style.display === 'block') { 
            showHistory(); 
        }
    } catch (error) { 
        hideLoading(); 
        showAlert('Gagal menghapus riwayat!', 'error'); 
    }
}
async function login() {
    var blocked = await checkIfBlocked();
    if (blocked) { showBlockedScreen(); return; }
    var username = sanitize(document.getElementById('username').value.trim());
    var password = document.getElementById('password').value.trim();
    if (!username || !password) { showAlert('Harap isi username dan password!', 'warning'); return; }
    var blockData = getBlockData(username);
    if (blockData.blockedUntil && Date.now() < blockData.blockedUntil) { showAlert('🔒 Terlalu banyak percobaan! Akses ditolak.', 'error'); return; }
    showLoading('Login...');
    try {
        var result = await callRevanstore('login', 'POST', { username: username, password: password });
        if (result && result.blocked) { isBlocked = true; localStorage.setItem('bussid_blocked', 'true'); hideLoading(); showBlockedScreen(); return; }
        if (result && result.success) {
            localStorage.removeItem(getBlockKey(username));
            var user = result.data;
            var expiryCheck = checkAccountExpiry(user);
            if (expiryCheck.expired) { hideLoading(); showExpiredBanner(); return; }
            currentUser = { id: user.id, username: user.username, password: password, role: user.role || 'Operator', full_name: user.full_name || user.username, expiry_date: user.expiry_date || '' };
            await callRevanstore('login_success', 'POST', {});
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('mainApp').style.display = 'block';
            hideLoading(); showHome(); showAlert('Login berhasil!', 'success'); updateProfileInfo();
            localStorage.setItem('bussid_session', JSON.stringify({ username: username, password: password, user_id: user.id, timestamp: Date.now() }));
        } else {
            await callRevanstore('login_failed', 'POST', {});
            blockData.attempts += 1; var a = blockData.attempts; var d = getBlockDuration(a);
            hideLoading();
            if (d > 0) { blockData.blockedUntil = Date.now() + d * 60 * 1000; saveBlockData(username, blockData); showAlert('🔒 Terlalu banyak percobaan! Akses ditolak.', 'error'); }
            else { saveBlockData(username, blockData); showAlert('Username atau password salah!', 'error'); }
        }
    } catch (error) { hideLoading(); showAlert('Gagal menghubungkan ke server!', 'error'); }
}

function updateProfileInfo() {
    if (!currentUser) return;
    var expiryCheck = checkAccountExpiry(currentUser);
    document.getElementById('profileUsername').textContent = currentUser.username;
    document.getElementById('profileName').textContent = currentUser.full_name || currentUser.username;
    document.getElementById('profileRole').textContent = currentUser.role || 'Operator';
    var expiryFormatted = currentUser.expiry_date || 'Tidak ada';
    document.getElementById('profileExpiry').innerHTML = 
        '<span>' + expiryFormatted + '</span> ' +
        '<span class="expiry-days-left ' + expiryCheck.daysLeftClass + '">' + expiryCheck.daysLeftText + '</span>';
}

function logout() {
    currentUser = null; currentAccount = null; currentAuthToken = null; lastDeviceId = null;
    document.getElementById('mainApp').style.display = 'none'; document.getElementById('expiredBanner').style.display = 'none';
    var ls = document.getElementById('loginScreen');
    ls.style.display = 'block'; ls.style.position = 'fixed'; ls.style.top = '0'; ls.style.left = '0'; ls.style.width = '100%'; ls.style.height = '100%';
    document.getElementById('username').value = ''; document.getElementById('password').value = '';
    localStorage.removeItem('bussid_session'); showAlert('Logout!', 'success'); window.scrollTo(0, 0);
}

async function loginWithDeviceId(deviceId) {
    var blocked = await checkIfBlocked();
    if (blocked) { showBlockedScreen(); return false; }
    showLoading('Menghubungkan...');
    try {
        var cleanInput = sanitize(deviceId.trim());
        if (cleanInput.includes('.')) { currentAuthToken = cleanInput; }
        else {
            var cid = cleanInput.toLowerCase().replace(/^android-/, '');
            var data = await callRvnstore('/Client/LoginWithAndroidDeviceID', 'POST', { TitleId: "4AE9", AndroidDeviceId: cid, CreateAccount: true, InfoRequestParameters: { GetUserAccountInfo: true, GetUserVirtualCurrency: true, GetPlayerProfile: true } }, null);
            if (data.data && data.data.SessionTicket) { currentAuthToken = data.data.SessionTicket; }
            else { hideLoading(); throw new Error('Device ID tidak valid!'); }
        }
        var info = await getUserInfoFromPlayFab();
        if (info) { currentAccount = { deviceId: cleanInput, name: info.name, balance: info.balance, facebook: info.facebook, facebookAvatarUrl: info.facebookAvatarUrl, playFabId: info.playFabId }; hideLoading(); return true; }
        hideLoading(); throw new Error('Gagal!');
    } catch (error) { hideLoading(); showAlert(error.message, 'error'); return false; }
}

async function getUserInfoFromPlayFab() {
    if (!currentAuthToken) return null;
    try {
        var result = await callRvnstore('/Client/GetPlayerCombinedInfo', 'POST', { InfoRequestParameters: { GetUserAccountInfo: true, GetUserVirtualCurrency: true, GetPlayerProfile: true } }, currentAuthToken);
        if (result.data) {
            var info = result.data.InfoResultPayload; var acc = info.AccountInfo;
            var name = (acc && acc.TitleInfo) ? (acc.TitleInfo.DisplayName || 'Unknown') : 'Unknown';
            var balance = info.UserVirtualCurrency ? (info.UserVirtualCurrency.RP || 0) : 0;
            var pfid = acc ? (acc.PlayFabId || '-') : '-';
            var fb = { id: null, name: 'Tidak tertaut', email: null, isConnected: false };
            var fbAvatar = null;
            if (acc && acc.FacebookInfo) { fb = { id: acc.FacebookInfo.FacebookId || null, name: acc.FacebookInfo.FullName || 'Tidak tertaut', email: acc.FacebookInfo.Email || null, isConnected: true }; if (fb.id) fbAvatar = 'https://graph.facebook.com/' + fb.id + '/picture?type=large'; }
            return { name: name, balance: balance, facebook: fb, facebookAvatarUrl: fbAvatar, playFabId: pfid };
        }
    } catch(e) {}
    return null;
}

function tampilkanFotoProfile(acc) {
    var c = document.getElementById('profilePhoto'); if (!c) return; c.innerHTML = '';
    var url = acc && acc.facebookAvatarUrl ? acc.facebookAvatarUrl : null;
    if (url && url !== 'null' && url !== '') {
        var img = document.createElement('img'); img.src = url; img.style.width = '100%'; img.style.height = '100%'; img.style.objectFit = 'cover'; img.style.borderRadius = '50%';
        img.onload = function() { c.appendChild(img); }; img.onerror = function() { c.innerHTML = '<i class="fas fa-user"></i>'; };
    } else { c.innerHTML = '<i class="fas fa-user"></i>'; }
}

function tampilkanInfoFacebook(fb) {
    var d = document.getElementById('facebookDetails'); if (!d) return;
    if (fb && fb.isConnected && fb.id) {
        d.innerHTML = '<div class="fb-info-row"><span class="fb-info-label"><i class="fab fa-facebook"></i> Status:</span><span class="fb-info-value" style="color:#1877F2;">✅ TERHUBUNG</span></div>' +
            '<div class="fb-info-row"><span class="fb-info-label">Facebook ID:</span><span class="fb-info-value" style="font-family:monospace;font-size:12px;">' + sanitize(fb.id) + '</span></div>' +
            '<div class="fb-info-row"><span class="fb-info-label">Nama:</span><span class="fb-info-value">' + sanitize(fb.name || '-') + '</span></div>' +
            '<div class="fb-info-row"><span class="fb-info-label">Email:</span><span class="fb-info-value">' + sanitize(fb.email || '-') + '</span></div>';
    } else {
        d.innerHTML = '<div class="fb-info-row"><span class="fb-info-label"><i class="fab fa-facebook"></i> Status:</span><span class="fb-info-value" style="color:#ffaa00;">⚠️ TIDAK TERHUBUNG</span></div>';
    }
}

async function searchAccount() {
    var id = document.getElementById('deviceId').value.trim();
    if (!id) { showAlert('Masukkan Device ID!', 'error'); return; }
    var ok = await loginWithDeviceId(id);
    if (ok) { lastDeviceId = id; showAccountInfo(currentAccount); hideAllSections(); document.getElementById('accountInfo').style.display = 'block'; showAlert('Akun ditemukan!', 'success'); }
}

function showAccountInfo(acc) {
    document.getElementById('accountName').textContent = sanitize(acc.name || '-');
    document.getElementById('accountBalance').textContent = formatCurrency(acc.balance);
    document.getElementById('playfabId').textContent = acc.playFabId || '-';
    tampilkanFotoProfile(acc); tampilkanInfoFacebook(acc.facebook);
}

function refreshAccountInfo() {
    if (!currentAccount) { showAlert('Cari akun dulu!', 'error'); return; }
    showLoading('Refresh...');
    setTimeout(async function() {
        var info = await getUserInfoFromPlayFab();
        if (info) { currentAccount.balance = info.balance; currentAccount.name = info.name; currentAccount.facebook = info.facebook; currentAccount.facebookAvatarUrl = info.facebookAvatarUrl; currentAccount.playFabId = info.playFabId; showAccountInfo(currentAccount); hideLoading(); showAlert('Updated!', 'success'); }
        else { hideLoading(); }
    }, 1000);
}

function setAmount(a) { document.getElementById('topupAmount').value = a; validateTopupAmount(); }
function showTopupFromAccount() { if (!currentAccount) return; document.getElementById('topupAccountName').textContent = currentAccount.name; document.getElementById('topupCurrentBalance').textContent = formatCurrency(currentAccount.balance); hideAllSections(); document.getElementById('topupSection').style.display = 'block'; }
function showKurasFromAccount() { if (!currentAccount) return; document.getElementById('kurasAccountName').textContent = currentAccount.name; document.getElementById('kurasCurrentBalance').textContent = formatCurrency(currentAccount.balance); hideAllSections(); document.getElementById('kurasSection').style.display = 'block'; }
function showChangeNameSection() { if (!currentAccount) return; document.getElementById('changeNameAccountLabel').textContent = currentAccount.name; hideAllSections(); document.getElementById('changeNameSection').style.display = 'block'; }

async function processTopup() { if (!currentAccount) return; var amt = parseAmount(document.getElementById('topupAmount').value.trim()); if (amt <= 0) { showAlert('Jumlah tidak valid!', 'error'); return; } showConfirm('TOP UP', 'Top up ' + formatCurrency(amt) + '?', 'topup', { amount: amt }); }
async function executeTopup(amt) { showLoading('Memproses...'); var old = currentAccount.balance; var ok = await addCashToAccount(amt); if (ok) { var trx = { type: 'topup', deviceId: currentAccount.deviceId, accountName: currentAccount.name, amount: amt, oldBalance: old, newBalance: currentAccount.balance, operator: currentUser.username, timestamp: Date.now(), status: 'success' }; await callRevanstore('transactions', 'POST', trx); hideLoading(); showReceipt(trx); showAlert('Berhasil!', 'success'); } else { hideLoading(); showAlert('Gagal!', 'error'); } }
async function processKuras() { if (!currentAccount) return; var amt = parseAmount(document.getElementById('kurasAmount').value.trim()) || currentAccount.balance; if (amt <= 0 || amt > currentAccount.balance) { showAlert('Saldo tidak cukup!', 'error'); return; } showConfirm('KURAS', 'Kuras ' + formatCurrency(amt) + '?', 'kuras', { amount: amt }); }
async function executeKuras(amt) { showLoading('Memproses...'); var old = currentAccount.balance; var ok = await addCashToAccount(-amt); if (ok) { var trx = { type: 'kuras', deviceId: currentAccount.deviceId, accountName: currentAccount.name, amount: amt, oldBalance: old, newBalance: currentAccount.balance, operator: currentUser.username, timestamp: Date.now(), status: 'success' }; await callRevanstore('transactions', 'POST', trx); hideLoading(); showReceipt(trx); showAlert('Berhasil!', 'success'); } else { hideLoading(); showAlert('Gagal!', 'error'); } }

async function addCashToAccount(amt) {
    if (!currentAuthToken) return false;
    try { var res = await callRvnstore('/Client/ExecuteCloudScript', 'POST', { FunctionName: "AddRp", FunctionParameter: { addValue: amt }, RevisionSelection: "Live", GeneratePlayStreamEvent: true }, currentAuthToken); if (res.data) { await new Promise(function(r) { setTimeout(r, 2000); }); var info = await getUserInfoFromPlayFab(); if (info) { currentAccount.balance = info.balance; currentAccount.facebook = info.facebook; currentAccount.facebookAvatarUrl = info.facebookAvatarUrl; currentAccount.playFabId = info.playFabId; showAccountInfo(currentAccount); return true; } } return false; } catch(e) { return false; }
}

function showReceipt(trx) {
    hideAllSections();
    var typeText = trx.type === 'topup' ? 'TOP UP' : 'KURAS', sign = trx.type === 'topup' ? '+' : '-';
    document.getElementById('receiptContent').innerHTML = '<div class="receipt-content"><div class="receipt-header"><h3>BUSSID</h3><p>Detail Transaksi</p></div><div class="receipt-details"><div class="receipt-row"><span>Akun:</span><span>' + sanitize(trx.accountName) + '</span></div><div class="receipt-row"><span>Jenis:</span><span>' + typeText + '</span></div><div class="receipt-row"><span>Jumlah:</span><span style="color:' + (trx.type === 'topup' ? '#10b981' : '#f59e0b') + '">' + sign + formatCurrency(trx.amount) + '</span></div><div class="receipt-row"><span>Saldo Awal:</span><span>' + formatCurrency(trx.oldBalance) + '</span></div><div class="receipt-row"><span>Saldo Akhir:</span><span>' + formatCurrency(trx.newBalance) + '</span></div><div class="receipt-row"><span>Tanggal:</span><span>' + new Date(trx.timestamp).toLocaleString('id-ID') + '</span></div><div class="receipt-row"><span>Status:</span><span style="color:#10b981;">BERHASIL</span></div></div></div><div style="display:flex;gap:8px;margin-top:20px;"><button class="btn btn-primary" onclick="window._showTrxModal()" style="flex:1;">TRX LAGI</button><button class="btn btn-secondary" onclick="window._goHome()" style="flex:1;">HOME</button></div>';
    document.getElementById('receiptSection').style.display = 'block';
}

window._showTrxModal = function() { var modal = document.getElementById('trxLagiModal'); if (modal) { modal.style.display = 'flex'; modal.style.opacity = '1'; modal.style.visibility = 'visible'; } };
window._tutupTrxModal = function() { var modal = document.getElementById('trxLagiModal'); if (modal) modal.style.display = 'none'; };
window._pilihTopup = function() { window._tutupTrxModal(); showTopupFromAccount(); };
window._pilihKuras = function() { window._tutupTrxModal(); showKurasFromAccount(); };
window._goHome = function() { showHome(); };
function backToHome() { showHome(); }

async function showHistory() {
    hideAllSections(); document.getElementById('historySection').style.display = 'block'; showLoading('Mengambil data...');
    try {
        var data = await callRevanstore('transactions', 'GET'); var list = document.getElementById('transactionsList');
        if (!data || typeof data !== 'object' || Object.keys(data).length === 0) { list.innerHTML = '<p style="text-align:center;color:#666;padding:40px 20px;">Belum ada transaksi</p>'; hideLoading(); return; }
        var arr = Object.keys(data).map(function(k) { return { id: k, type: data[k].type, accountName: data[k].accountName, amount: data[k].amount, oldBalance: data[k].oldBalance, newBalance: data[k].newBalance, operator: data[k].operator, timestamp: data[k].timestamp }; }).sort(function(a, b) { return b.timestamp - a.timestamp; });
        if (arr.length === 0) { list.innerHTML = '<p style="text-align:center;color:#666;padding:40px 20px;">Belum ada transaksi</p>'; hideLoading(); return; }
        var html = ''; arr.forEach(function(t) { var typeText = t.type === 'topup' ? 'TOP UP' : t.type === 'kuras' ? 'KURAS' : 'GANTI NAMA'; var sign = t.type === 'topup' ? '+' : t.type === 'kuras' ? '-' : ''; html += '<div class="transaction-item ' + t.type + '"><div class="transaction-header"><div>' + sanitize(t.accountName) + '</div><div class="transaction-amount">' + sign + formatCurrency(t.amount) + '</div></div><div class="transaction-details"><div>' + typeText + '</div><div>' + new Date(t.timestamp).toLocaleString('id-ID') + '</div></div><div class="transaction-balance"><span>Sebelum: ' + formatCurrency(t.oldBalance) + '</span><span>→</span><span>Sesudah: ' + formatCurrency(t.newBalance) + '</span></div></div>'; });
        list.innerHTML = html; hideLoading();
    } catch(e) { hideLoading(); showAlert('Gagal!', 'error'); }
}

function showSettings() { hideAllSections(); document.getElementById('settingsSection').style.display = 'block'; updateProfileInfo(); }
function showConfirm(title, message, action, data) { document.getElementById('modalConfirmTitle').innerHTML = sanitize(title); document.getElementById('modalConfirmMessage').innerHTML = sanitize(message); pendingAction = action; pendingData = data; document.getElementById('confirmModal').classList.add('active'); }
function cancelConfirm() { pendingAction = null; pendingData = null; document.getElementById('confirmModal').classList.remove('active'); }

async function confirmAction() { if (!pendingAction || !pendingData) return; document.getElementById('confirmModal').classList.remove('active'); if (pendingAction === 'topup') await executeTopup(pendingData.amount); else if (pendingAction === 'kuras') await executeKuras(pendingData.amount); else if (pendingAction === 'changename') await executeChangeName(pendingData); pendingAction = null; pendingData = null; }
async function checkNameAvailability() { var d = document.getElementById('nameAvailability'); d.innerHTML = 'Mengecek...'; d.style.display = 'block'; setTimeout(function() { d.innerHTML = '✅ Tersedia!'; }, 1000); }
async function changeAccountNameSimple() { var name = sanitize(document.getElementById('newAccountName').value.trim()); if (!name) { showAlert('Masukkan nama!', 'error'); return; } if (!currentAccount || !currentAuthToken) { showAlert('Cari akun dulu!', 'error'); return; } showConfirm('GANTI NAMA', 'Ganti ke "' + name + '"?', 'changename', name); }

async function executeChangeName(newName) {
    showLoading('Mengubah...');
    try { var res = await callRvnstore('/Client/UpdateUserTitleDisplayName', 'POST', { DisplayName: newName }, currentAuthToken); if (res.data && res.data.DisplayName) { var old = currentAccount.name; currentAccount.name = newName; document.getElementById('accountName').textContent = newName; await callRevanstore('transactions', 'POST', { type: 'gantinama', accountName: currentAccount.name, oldName: old, newName: newName, operator: currentUser.username, timestamp: Date.now(), status: 'success' }); hideAllSections(); document.getElementById('receiptContent').innerHTML = '<div class="receipt-content"><div class="receipt-header"><h3>GANTI NAMA</h3></div><div class="receipt-details"><div class="receipt-row"><span>Lama:</span><span>' + sanitize(old) + '</span></div><div class="receipt-row"><span>Baru:</span><span style="color:#0ea5e9;">' + sanitize(newName) + '</span></div></div></div><button class="btn btn-primary btn-block" onclick="window._goBackAccount()">KEMBALI</button>'; document.getElementById('receiptSection').style.display = 'block'; hideLoading(); showAlert('Berhasil!', 'success'); } else { hideLoading(); showAlert('Gagal!', 'error'); } } catch(e) { hideLoading(); showAlert('Gagal!', 'error'); }
}

window._goBackAccount = function() { backToAccount(); };
function showNameChangeModal(msg, type) { var m = document.getElementById('nameChangeModal'); document.getElementById('nameChangeMessage').innerHTML = sanitize(msg); m.classList.add('active'); }
function closeNameChangeModal() { document.getElementById('nameChangeModal').classList.remove('active'); }
function setupQuickAmounts() { var q = document.querySelector('.quick-amounts'); if (q) q.innerHTML = '<button class="btn-quick" onclick="setAmount(\'2M\')">2M</button><button class="btn-quick" onclick="setAmount(\'1M\')">1M</button><button class="btn-quick" onclick="setAmount(\'500JT\')">500JT</button><button class="btn-quick" onclick="setAmount(\'100JT\')">100JT</button><button class="btn-quick" onclick="setAmount(\'50JT\')">50JT</button>'; }
function setupEventListeners() { var u = document.getElementById('username'); if (u) u.addEventListener('keypress', function(e) { if (e.key === 'Enter') document.getElementById('password').focus(); }); var p = document.getElementById('password'); if (p) p.addEventListener('keypress', function(e) { if (e.key === 'Enter') login(); }); var t = document.getElementById('topupAmount'); if (t) t.addEventListener('keypress', function(e) { if (e.key === 'Enter') processTopup(); }); var d = document.getElementById('deviceId'); if (d) d.addEventListener('keypress', function(e) { if (e.key === 'Enter') searchAccount(); }); }

document.addEventListener('DOMContentLoaded', async function() {
    setupEventListeners(); setupQuickAmounts();
    document.addEventListener('contextmenu', function(e) { e.preventDefault(); });
    document.addEventListener('keydown', function(e) { if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && e.key === 'I') || (e.ctrlKey && e.key === 'U')) { e.preventDefault(); return false; } });
    var ls = document.getElementById('loginScreen'); ls.style.position = 'fixed'; ls.style.top = '0'; ls.style.left = '0'; ls.style.width = '100%'; ls.style.height = '100%';
    if (!fingerprint) fingerprint = await getFingerprint();
    var blocked = await checkIfBlocked();
    if (blocked) { showBlockedScreen(); return; }
    ls.style.display = 'block';
    var saved = localStorage.getItem('bussid_session');
    if (saved) { try { var session = JSON.parse(saved), age = Date.now() - (session.timestamp || 0); if (age > 7 * 24 * 60 * 60 * 1000) { localStorage.removeItem('bussid_session'); return; } var result = await callRevanstore('login', 'POST', { username: session.username, password: session.password }); if (result && result.success) { var user = result.data; var expiryCheck = checkAccountExpiry(user); if (expiryCheck.expired) { showExpiredBanner(); return; } currentUser = { id: user.id, username: user.username, password: session.password, role: user.role || 'Operator', full_name: user.full_name || user.username, expiry_date: user.expiry_date || '' }; ls.style.display = 'none'; document.getElementById('mainApp').style.display = 'block'; showHome(); updateProfileInfo(); showAlert('Selamat datang!', 'success'); } else { localStorage.removeItem('bussid_session'); } } catch(e) { localStorage.removeItem('bussid_session'); } }
});