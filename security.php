<?php
/**
 * Модуль безопасности
 * Содержит функции для защиты от различных уязвимостей
 */

/**
 * Генерация и проверка CSRF токена
 */
function generateCsrfToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        die('Ошибка CSRF защиты. Неверный токен.');
    }
    // Обновляем токен после использования для дополнительной защиты
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    return true;
}

/**
 * Очистка данных от XSS
 */
function xssClean($data) {
    if (is_array($data)) {
        return array_map('xssClean', $data);
    }
    return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Безопасный вывод в HTML контексте
 */
function safeHtml($data) {
    return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Безопасный вывод в JavaScript контексте
 */
function safeJs($data) {
    return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
}

/**
 * Безопасный вывод в URL контексте
 */
function safeUrl($data) {
    return urlencode($data);
}

/**
 * Валидация и очистка входящих данных
 */
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    // Удаляем пробелы в начале и конце
    $data = trim($data);
    // Удаляем нулевые байты
    $data = str_replace(chr(0), '', $data);
    // Преобразуем специальные символы
    return $data;
}

/**
 * Настройка заголовков безопасности
 */
function setSecurityHeaders() {
    // Защита от XSS через заголовки
    header('X-XSS-Protection: 1; mode=block');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    
    // Content Security Policy
    header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'");
    
    // Strict Transport Security (если используете HTTPS)
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    
    // Защита от кэширования чувствительных данных
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

/**
 * Проверка Referer для защиты от CSRF
 */
function validateReferer() {
    if (!isset($_SERVER['HTTP_REFERER'])) {
        // Для первого запроса с формы реферер может отсутствовать
        return true;
    }
    
    $referer = parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST);
    $host = $_SERVER['HTTP_HOST'];
    
    if ($referer !== $host) {
        die('Подозрительный запрос. Неверный источник.');
    }
}

/**
 * Логирование ошибок и подозрительной активности
 */
function logSecurityEvent($event, $data = []) {
    $logFile = __DIR__ . '/security.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    $logEntry = [
        'timestamp' => $timestamp,
        'ip' => $ip,
        'event' => $event,
        'user_agent' => $userAgent,
        'data' => $data
    ];
    
    // Не логируем пароли и чувствительные данные
    unset($logEntry['data']['password']);
    unset($logEntry['data']['password_hash']);
    
    file_put_contents(
        $logFile, 
        json_encode($logEntry, JSON_UNESCAPED_UNICODE) . "\n", 
        FILE_APPEND | LOCK_EX
    );
}

/**
 * Защита от брутфорса
 */
function checkBruteForce($login, $ip) {
    $attemptsFile = sys_get_temp_dir() . '/login_attempts.json';
    $maxAttempts = 5;
    $blockTime = 300; // 5 минут
    
    $attempts = [];
    if (file_exists($attemptsFile)) {
        $attempts = json_decode(file_get_contents($attemptsFile), true) ?: [];
    }
    
    // Очищаем старые попытки
    $attempts = array_filter($attempts, function($attempt) {
        return $attempt['time'] > (time() - 3600);
    });
    
    // Считаем попытки
    $userAttempts = array_filter($attempts, function($attempt) use ($login, $ip) {
        return $attempt['login'] === $login || $attempt['ip'] === $ip;
    });
    
    $recentAttempts = array_filter($userAttempts, function($attempt) use ($blockTime) {
        return $attempt['time'] > (time() - $blockTime);
    });
    
    if (count($recentAttempts) >= $maxAttempts) {
        $lastAttempt = max(array_column($recentAttempts, 'time'));
        $waitTime = $blockTime - (time() - $lastAttempt);
        
        if ($waitTime > 0) {
            logSecurityEvent('brute_force_blocked', [
                'login' => $login,
                'ip' => $ip,
                'attempts' => count($recentAttempts)
            ]);
            
            return [
                'blocked' => true,
                'wait' => $waitTime
            ];
        }
    }
    
    // Добавляем новую попытку
    $attempts[] = [
        'login' => $login,
        'ip' => $ip,
        'time' => time()
    ];
    
    file_put_contents($attemptsFile, json_encode($attempts), LOCK_EX);
    
    return ['blocked' => false];
}

/**
 * Безопасное подключение файлов (защита от Include уязвимости)
 */
function safeInclude($file) {
    // Белый список разрешенных файлов
    $allowedFiles = [
        'form.php',
        'login_form.php',
        'admin_panel.php'
    ];
    
    // Проверяем, что файл в белом списке
    if (!in_array(basename($file), $allowedFiles)) {
        logSecurityEvent('include_attempt_blocked', ['file' => $file]);
        die('Доступ запрещен');
    }
    
    $fullPath = __DIR__ . '/' . basename($file);
    
    if (!file_exists($fullPath)) {
        die('Файл не найден');
    }
    
    include $fullPath;
}

/**
 * Безопасная загрузка файлов
 */
function secureUpload($file, $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'], $maxSize = 5242880) {
    $errors = [];
    
    // Проверка на ошибки загрузки
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'Ошибка при загрузке файла';
        return ['success' => false, 'errors' => $errors];
    }
    
    // Проверка размера файла
    if ($file['size'] > $maxSize) {
        $errors[] = 'Файл слишком большой. Максимальный размер: ' . ($maxSize / 1024 / 1024) . 'MB';
    }
    
    // Проверка MIME-типа
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    if (!in_array($mimeType, $allowedTypes)) {
        $errors[] = 'Недопустимый тип файла: ' . $mimeType;
        logSecurityEvent('upload_blocked', [
            'filename' => $file['name'],
            'mime_type' => $mimeType,
            'size' => $file['size']
        ]);
    }
    
    // Проверка расширения файла
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    
    if (!in_array($extension, $allowedExtensions)) {
        $errors[] = 'Недопустимое расширение файла';
    }
    
    // Проверка содержимого файла на вредоносный код
    $content = file_get_contents($file['tmp_name']);
    if (
        strpos($content, '<?php') !== false || 
        strpos($content, '<?=') !== false ||
        strpos($content, '<script') !== false
    ) {
        $errors[] = 'Файл содержит потенциально опасное содержимое';
        logSecurityEvent('malicious_content_detected', ['filename' => $file['name']]);
    }
    
    if (!empty($errors)) {
        return ['success' => false, 'errors' => $errors];
    }
    
    // Генерируем безопасное имя файла
    $newFilename = bin2hex(random_bytes(16)) . '.' . $extension;
    $uploadDir = __DIR__ . '/uploads/';
    
    // Создаем директорию если не существует
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }
    
    // Защита от перезаписи файлов
    if (file_exists($uploadDir . $newFilename)) {
        $newFilename = bin2hex(random_bytes(16)) . '.' . $extension;
    }
    
    $destination = $uploadDir . $newFilename;
    
    if (move_uploaded_file($file['tmp_name'], $destination)) {
        // Устанавливаем правильные разрешения
        chmod($destination, 0644);
        
        return [
            'success' => true,
            'filename' => $newFilename,
            'path' => 'uploads/' . $newFilename
        ];
    }
    
    return ['success' => false, 'errors' => ['Не удалось сохранить файл']];
}