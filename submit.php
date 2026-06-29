<?php
session_start();
require_once 'db.php';
require_once 'security.php';
require_once 'functions.php';

// Устанавливаем защитные заголовки
setSecurityHeaders();

$pdo = getDatabase();

// Проверяем метод запроса
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit();
}

// Проверяем CSRF токен
if (!isset($_POST['csrf_token'])) {
    logSecurityEvent('csrf_attack_attempt', ['reason' => 'token_missing']);
    die('Ошибка безопасности: отсутствует CSRF токен');
}

validateCsrfToken($_POST['csrf_token']);

// Проверяем Referer
validateReferer();

$errors = [];

// Очищаем и валидируем входящие данные
$data = [
    'full_name' => sanitizeInput($_POST['full_name'] ?? ''),
    'phone' => sanitizeInput($_POST['phone'] ?? ''),
    'email' => sanitizeInput($_POST['email'] ?? ''),
    'birth_date' => sanitizeInput($_POST['birth_date'] ?? ''),
    'gender' => sanitizeInput($_POST['gender'] ?? ''),
    'biography' => sanitizeInput($_POST['biography'] ?? ''),
    'agreement' => isset($_POST['agreement']),
    'languages' => array_map('intval', $_POST['languages'] ?? [])
];

// Валидация
$errors = validateUserData($data);

// Сохраняем в куки с флагами безопасности
$cookieOptions = [
    'expires' => time() + 31536000,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
];

foreach (['full_name', 'phone', 'email', 'birth_date', 'gender', 'biography', 'agreement'] as $field) {
    setcookie($field, $data[$field], $cookieOptions);
}
setcookie('languages', json_encode($data['languages']), $cookieOptions);

if (!empty($errors)) {
    foreach ($errors as $field => $error) {
        setcookie($field . '_error', $error, [
            'expires' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }
    header('Location: index.php');
    exit();
}

try {
    $pdo->beginTransaction();

    if (isset($_SESSION['user_id'])) {
        // Обновление существующего пользователя
        updateUserData($pdo, $_SESSION['user_id'], $data);
        
        setcookie('success', 'Данные успешно обновлены!', [
            'expires' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        logSecurityEvent('user_updated', ['user_id' => $_SESSION['user_id']]);
    } else {
        // Создание нового пользователя
        $credentials = createUser($pdo, $data);
        
        setcookie('generated_login', $credentials['login'], [
            'expires' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        setcookie('generated_password', $credentials['password'], [
            'expires' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        setcookie('success', 'Регистрация успешно завершена!', [
            'expires' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        logSecurityEvent('user_created', ['login' => $credentials['login']]);
    }

    $pdo->commit();
    
} catch (Exception $e) {
    $pdo->rollBack();
    error_log('Submit error: ' . $e->getMessage());
    logSecurityEvent('submit_error', ['error' => $e->getMessage()]);
    
    die('Произошла ошибка при сохранении данных. Пожалуйста, попробуйте позже.');
}

header('Location: index.php');
exit();