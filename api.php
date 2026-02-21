<?php

define('ADMIN_PASSWORD', 'changeme');
define('KEYS_FILE',      __DIR__ . '/data/keys.json');
define('LIBRARIES_FILE', __DIR__ . '/data/libraries.json');
define('SESSION_FILE',   __DIR__ . '/data/sessions.json');
define('LIBRARIES_DIR',  __DIR__ . '/AzxLibraries');
define('MAX_FILE_SIZE',  20 * 1024 * 1024); // 20 MB
define('AES_KEY_B64',    'ijIe7lzCGmmunuhiZ6I/f97NNBAVlLmhaEsfDZJe8eU=');
define('GAME_ID',        'AzxiePanel');
define('SECRET_SALT',    'Nh3Dv2WJ9jxfsbEzqWjRlA4KgFY9VQ8H');
define('SUCCESS_STATUS', 945734);


header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }


if (!is_dir(__DIR__ . '/data')) {
    mkdir(__DIR__ . '/data', 0755, true);
}
if (!is_dir(LIBRARIES_DIR)) {
    mkdir(LIBRARIES_DIR, 0755, true);
}

$action = trim($_REQUEST['action'] ?? '');

switch ($action) {
    case 'ping':              handlePing();              break;
    case 'admin_login':       handleAdminLogin();        break;
    case 'generate_keys':     handleGenerateKeys();      break;
    case 'list_keys':         handleListKeys();          break;
    case 'get_stats':         handleGetStats();          break;
    case 'delete_key':        handleDeleteKey();         break;
    case 'reset_hwid':        handleResetHWID();         break;
    case 'upload_library':    handleUploadLibrary();     break;
    case 'list_libraries':    handleListLibraries();     break;
    case 'delete_library':    handleDeleteLibrary();     break;
    case 'download_library':  handleDownloadLibrary();   break;
    case 'login':             handleLogin();             break;
    case 'connect':           handleConnect();           break;
    default:                  out(['success' => false, 'message' => "Unknown action: '$action'"]);
}

function loadKeys(): array {
    if (!file_exists(KEYS_FILE)) return [];
    $d = json_decode(file_get_contents(KEYS_FILE), true);
    return is_array($d) ? $d : [];
}

function saveKeys(array $keys): void {
    file_put_contents(KEYS_FILE, json_encode($keys, JSON_PRETTY_PRINT), LOCK_EX);
}

function loadLibraries(): array {
    if (!file_exists(LIBRARIES_FILE)) return [];
    $d = json_decode(file_get_contents(LIBRARIES_FILE), true);
    return is_array($d) ? $d : [];
}

function saveLibraries(array $libs): void {
    file_put_contents(LIBRARIES_FILE, json_encode($libs, JSON_PRETTY_PRINT), LOCK_EX);
}

function loadSessions(): array {
    if (!file_exists(SESSION_FILE)) return [];
    $d = json_decode(file_get_contents(SESSION_FILE), true);
    return is_array($d) ? $d : [];
}

function saveSessions(array $s): void {
    file_put_contents(SESSION_FILE, json_encode($s, JSON_PRETTY_PRINT), LOCK_EX);
}

function post(string $k): string {
    return isset($_POST[$k]) ? trim((string)$_POST[$k]) : '';
}

function out(array $data): void {
    echo json_encode($data);
    exit;
}

function makeKey(string $customName = ''): string {
    $randomPart = bin2hex(random_bytes(5));
    $prefix = ($customName !== '') ? $customName : 'Azxion';
    return "{$prefix}-{$randomPart}";
}

function requireAdmin(): void {
    $token    = post('token');
    if (!$token) out(['success' => false, 'message' => 'Unauthorized']);
    $sessions = loadSessions();
    $sessions = array_filter($sessions, fn($s) => ($s['exp'] ?? 0) > time());
    if (!isset($sessions[$token])) out(['success' => false, 'message' => 'Session expired. Please log in again.']);
    saveSessions($sessions);
}


function handlePing(): void {
    out(['success' => true, 'status' => 'online']);
}

function handleAdminLogin(): void {
    $pass = post('password');
    if (!$pass) out(['success' => false, 'message' => 'Password required.']);
    if (!hash_equals((string)ADMIN_PASSWORD, $pass)) out(['success' => false, 'message' => 'Invalid password.']);

    $token    = bin2hex(random_bytes(32));
    $sessions = loadSessions();
    $sessions = array_filter($sessions, fn($s) => ($s['exp'] ?? 0) > time());
    $sessions[$token] = ['exp' => time() + 7200];
    saveSessions($sessions);

    out(['success' => true, 'token' => $token]);
}

function handleGenerateKeys(): void {
    requireAdmin();
    $duration   = (int)post('duration');
    $qty        = min(100, max(1, (int)(post('qty') ?: 1)));
    $note       = post('note');
    $customName = (string)post('custom_name');
    
    $expires  = $duration > 0 ? date('Y-m-d H:i:s', strtotime("+{$duration} days")) : null;

    $keys    = loadKeys();
    $newKeys = [];
    for ($i = 0; $i < $qty; $i++) {
        do { $k = makeKey($customName); } while (isset($keys[$k]));
        $keys[$k] = ['key' => $k, 'status' => 'unused', 'hwid' => null, 'expires' => $expires, 'note' => $note ?: null, 'created' => date('Y-m-d H:i:s'), 'last_used' => null];
        $newKeys[] = $k;
    }
    saveKeys($keys);
    out(['success' => true, 'keys' => $newKeys]);
}

function handleListKeys(): void {
    requireAdmin();
    $search = strtolower(post('search'));
    $filter = post('status');
    $keys   = loadKeys();
    $rows   = [];
    foreach ($keys as $k => $row) {
        if ($filter && $row['status'] !== $filter) continue;
        if ($search && strpos(strtolower($k), $search) === false && strpos(strtolower((string)$row['note']), $search) === false) continue;
        $rows[] = $row;
    }
    usort($rows, fn($a, $b) => strcmp($b['created'], $a['created']));
    out(['success' => true, 'keys' => array_slice($rows, 0, 200)]);
}

function handleGetStats(): void {
    requireAdmin();
    $keys = loadKeys();
    $total = count($keys);
    $active = $unused = $expired = $banned = 0;
    foreach ($keys as $row) {
        if ($row['status'] !== 'banned' && $row['status'] !== 'expired' && !empty($row['expires']) && strtotime($row['expires']) < time()) $row['status'] = 'expired';
        match($row['status']) { 'active' => $active++, 'unused' => $unused++, 'expired' => $expired++, 'banned' => $banned++, default => null };
    }
    out(['success' => true, 'total' => $total, 'active' => $active, 'used' => $active + $expired, 'expired' => $expired, 'unused' => $unused, 'banned' => $banned]);
}

function handleDeleteKey(): void {
    requireAdmin();
    $keys = loadKeys();
    unset($keys[post('key')]);
    saveKeys($keys);
    out(['success' => true]);
}

function handleResetHWID(): void {
    requireAdmin();
    $k    = post('key');
    $keys = loadKeys();
    if (isset($keys[$k])) { $keys[$k]['hwid'] = null; $keys[$k]['status'] = 'unused'; saveKeys($keys); }
    out(['success' => true]);
}

function handleUploadLibrary(): void {
    requireAdmin();

    if (!isset($_FILES['library_file'])) {
        out(['success' => false, 'message' => 'No file uploaded.']);
    }

    $file = $_FILES['library_file'];
    $libName = post('lib_name');
    $libVersion = post('lib_version');
    $libDescription = post('lib_description');

    if (!$libName) {
        out(['success' => false, 'message' => 'Library name is required.']);
    }

    if ($file['error'] !== UPLOAD_ERR_OK) {
        out(['success' => false, 'message' => 'Upload error: ' . $file['error']]);
    }

    if ($file['size'] > MAX_FILE_SIZE) {
        out(['success' => false, 'message' => 'File exceeds 20 MB limit.']);
    }

    if (!preg_match('/\.so$/', $file['name'])) {
        out(['success' => false, 'message' => 'Only .SO files are allowed.']);
    }

    $filename = basename($file['name']);
    $filepath = LIBRARIES_DIR . '/' . $filename;

    if (!move_uploaded_file($file['tmp_name'], $filepath)) {
        out(['success' => false, 'message' => 'Failed to save file.']);
    }

    $libs = loadLibraries();
    $libs[$filename] = [
        'filename' => $filename,
        'size' => filesize($filepath),
        'version' => $libVersion ?: null,
        'description' => $libDescription ?: null,
        'uploaded' => date('Y-m-d H:i:s')
    ];
    saveLibraries($libs);

    out(['success' => true, 'message' => 'Library uploaded successfully.']);
}

function handleListLibraries(): void {
    requireAdmin();
    $search = strtolower(post('search'));
    $libs = loadLibraries();
    $rows = [];

    foreach ($libs as $lib) {
        if ($search && strpos(strtolower($lib['filename']), $search) === false) {
            continue;
        }
        $rows[] = $lib;
    }

    usort($rows, fn($a, $b) => strcmp($b['uploaded'], $a['uploaded']));
    out(['success' => true, 'libraries' => array_slice($rows, 0, 200)]);
}

function handleDeleteLibrary(): void {
    requireAdmin();
    $filename = basename(post('filename'));
    $filepath = LIBRARIES_DIR . '/' . $filename;

    if (file_exists($filepath)) {
        unlink($filepath);
    }

    $libs = loadLibraries();
    unset($libs[$filename]);
    saveLibraries($libs);

    out(['success' => true]);
}

function handleDownloadLibrary(): void {
    requireAdmin();
    $filename = basename($_GET['filename'] ?? '');
    $filepath = LIBRARIES_DIR . '/' . $filename;

    if (!file_exists($filepath) || !is_file($filepath)) {
        http_response_code(404);
        out(['success' => false, 'message' => 'File not found.']);
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
    header('Content-Length: ' . filesize($filepath));
    readfile($filepath);
    exit;
}

function handleLogin(): void {
    $uk = post('user_key');
    if (!$uk) out(['success' => false, 'message' => 'Key required.']);
    $keys = loadKeys();
    if (!isset($keys[$uk])) out(['success' => false, 'message' => 'Invalid key.']);
    $row = $keys[$uk];
    if ($row['status'] === 'banned') out(['success' => false, 'message' => 'Key is banned.']);
    if (!empty($row['expires']) && strtotime($row['expires']) < time()) {
        $keys[$uk]['status'] = 'expired'; saveKeys($keys);
        out(['success' => false, 'message' => 'Key has expired.']);
    }
    if ($row['status'] === 'expired') out(['success' => false, 'message' => 'Key has expired.']);
    out(['success' => true, 'expiry' => $row['expires'] ?: 'Lifetime']);
}

function handleConnect(): void {
    $aesKey = base64_decode(AES_KEY_B64);
    $game = post('game'); $auth = post('auth'); $uk = post('user_key');
    $serial = post('serial'); $t = (int)post('t'); $sig = post('sig');

    if ($game !== GAME_ID || abs(time()-$t) > 60) { sendEncErr('Rejected', $aesKey); return; }
    if (!hash_equals(hash_hmac('sha256', "game={$game}&auth={$auth}&user_key={$uk}&serial={$serial}&t={$t}", $aesKey), $sig)) { sendEncErr('Signature mismatch', $aesKey); return; }

    $keys = loadKeys();
    if (!isset($keys[$uk])) { sendEncErr('Key not found', $aesKey); return; }
    $row = $keys[$uk];
    if ($row['status'] === 'banned') { sendEncErr('Banned', $aesKey); return; }
    if (!empty($row['expires']) && strtotime($row['expires']) < time()) { $keys[$uk]['status']='expired'; saveKeys($keys); sendEncErr('Expired', $aesKey); return; }
    if (!empty($row['hwid']) && $row['hwid'] !== $serial) { sendEncErr('HWID mismatch', $aesKey); return; }
    if (empty($row['hwid'])) { $keys[$uk]['hwid']=$serial; $keys[$uk]['status']='active'; }
    $keys[$uk]['last_used'] = date('Y-m-d H:i:s');
    saveKeys($keys);

    $checked = md5(GAME_ID.'-'.$uk.'-'.$serial.'-'.$auth.'-'.$t.'-'.SECRET_SALT);
    sendEncPayload(json_encode(['status'=>SUCCESS_STATUS,'data'=>['token'=>md5($uk),'rng'=>time(),'expiredDate'=>$row['expires']?:'Lifetime','checked'=>$checked]]), $aesKey);
}

function sendEncPayload(string $json, string $key): void {
    $iv=''; $tag='';
    $iv = random_bytes(12);
    $ct = openssl_encrypt($json,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$iv,$tag);
    $b64 = base64_encode($iv.$tag.$ct);
    out(['enc'=>true,'payload'=>$b64,'hmac'=>hash_hmac('sha256',$b64,$key)]);
}

function sendEncErr(string $r, string $k): void {
    sendEncPayload(json_encode(['status'=>0,'reason'=>$r]),$k);
}