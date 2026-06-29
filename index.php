<?php
session_start();
require_once 'db.php';
require_once 'security.php';

// Устанавливаем защитные заголовки
setSecurityHeaders();

$pdo = getDatabase();
$errors = [];
$values = [];
$selectedLanguages = [];

$formFields = [
    'full_name',
    'phone',
    'email',
    'birth_date',
    'gender',
    'biography',
    'agreement',
    'languages'
];

/* АВТОРИЗОВАН ПОЛЬЗОВАТЕЛЬ */
if (isset($_SESSION['user_id'])) {
    try {
        $user = fetchOne("
            SELECT * FROM applications WHERE id = ?
        ", [$_SESSION['user_id']]);

        if ($user) {
            $values = array_map('sanitizeInput', $user);
            
            $languagesResult = fetchAll("
                SELECT language_id FROM application_language WHERE application_id = ?
            ", [$_SESSION['user_id']]);
            
            $selectedLanguages = array_column($languagesResult, 'language_id');
        }
    } catch (PDOException $e) {
        error_log('Error loading user data: ' . $e->getMessage());
        $errors['general'] = 'Ошибка загрузки данных';
    }
} else {
    /* COOKIE ИЗ ЛР4 */
    foreach ($formFields as $field) {
        $values[$field] = isset($_COOKIE[$field]) ? sanitizeInput($_COOKIE[$field]) : '';
    }
}

/* ОШИБКИ */
foreach ($formFields as $field) {
    $errorKey = $field . '_error';
    if (isset($_COOKIE[$errorKey])) {
        $errors[$field] = xssClean($_COOKIE[$errorKey]);
        setcookie($errorKey, '', time() - 3600, '/', '', true, true);
    }
}

/* УСПЕХ */
$successMessage = '';
if (isset($_COOKIE['success'])) {
    $successMessage = xssClean($_COOKIE['success']);
    setcookie('success', '', time() - 3600, '/', '', true, true);
}

/* ЛОГИН/ПАРОЛЬ */
$generatedLogin = isset($_COOKIE['generated_login']) ? xssClean($_COOKIE['generated_login']) : '';
$generatedPassword = isset($_COOKIE['generated_password']) ? xssClean($_COOKIE['generated_password']) : '';

if ($generatedLogin) {
    setcookie('generated_login', '', time() - 3600, '/', '', true, true);
    setcookie('generated_password', '', time() - 3600, '/', '', true, true);
}

/* ЯЗЫКИ */
try {
    $languages = fetchAll("SELECT * FROM languages ORDER BY title");
} catch (PDOException $e) {
    error_log('Error loading languages: ' . $e->getMessage());
    $languages = [];
}

// Генерируем CSRF токен
$csrfToken = generateCsrfToken();

include 'form.php';