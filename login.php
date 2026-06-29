<?php
session_start();
require_once 'db.php';
require_once 'security.php';

setSecurityHeaders();

$error = '';
$login = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Проверяем CSRF токен
    validateCsrfToken($_POST['csrf_token'] ?? '');
    
    $login = sanitizeInput($_POST['login'] ?? '');
    $password = $_POST['password'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];
    
    // Проверяем брутфорс
    $bruteCheck = checkBruteForce($login, $ip);
    if ($bruteCheck['blocked']) {
        $waitMinutes = ceil($bruteCheck['wait'] / 60);
        $error = "Слишком много попыток. Попробуйте через {$waitMinutes} мин.";
        logSecurityEvent('login_blocked', ['login' => $login]);
    } else {
        try {
            $user = fetchOne("
                SELECT id, login, password_hash 
                FROM applications 
                WHERE login = :login
            ", ['login' => $login]);
            
            if ($user && password_verify($password, $user['password_hash'])) {
                // Успешный вход
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_login'] = $user['login'];
                
                // Обновляем хеш если нужно
                if (password_needs_rehash($user['password_hash'], PASSWORD_BCRYPT, ['cost' => 12])) {
                    $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                    safeQuery("UPDATE applications SET password_hash = :hash WHERE id = :id", [
                        'hash' => $newHash,
                        'id' => $user['id']
                    ]);
                }
                
                logSecurityEvent('login_success', ['login' => $login]);
                session_regenerate_id(true);
                
                header('Location: index.php');
                exit();
            } else {
                $error = 'Неверный логин или пароль';
                logSecurityEvent('login_failed', ['login' => $login]);
            }
        } catch (PDOException $e) {
            error_log('Login error: ' . $e->getMessage());
            $error = 'Ошибка входа. Попробуйте позже.';
        }
    }
}

$csrfToken = generateCsrfToken();
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в систему</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="card">
        <h1>Вход в систему</h1>
        <p class="author">Проект выполнила: Рыбалко Евгения</p>
        
        <?php if (!empty($error)): ?>
            <div class="message"><?= safeHtml($error) ?></div>
        <?php endif; ?>
        
        <form method="POST" action="login.php">
            <input type="hidden" name="csrf_token" value="<?= safeHtml($csrfToken) ?>">
            
            <div class="form-group">
                <label for="login">Логин</label>
                <input 
                    type="text" 
                    id="login"
                    name="login" 
                    value="<?= safeHtml($login) ?>"
                    required 
                    autocomplete="username"
                    maxlength="50"
                >
            </div>
            
            <div class="form-group">
                <label for="password">Пароль</label>
                <input 
                    type="password" 
                    id="password"
                    name="password" 
                    required 
                    autocomplete="current-password"
                >
            </div>
            
            <button type="submit">Войти</button>
        </form>
        
        <div class="bottom-link">
            <a href="index.php">Назад к форме</a>
        </div>
    </div>
</body>
</html>