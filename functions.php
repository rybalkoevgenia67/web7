<?php
/**
 * Общие функции с улучшенной безопасностью
 */

/**
 * Валидация данных пользователя
 */
function validateUserData($data) {
    $errors = [];

    // ФИО
    if (
        empty($data['full_name']) ||
        !preg_match('/^[а-яА-Яa-zA-Z\s\-]{1,150}$/u', $data['full_name'])
    ) {
        $errors['full_name'] = 'Допустимы буквы, пробелы и дефис (до 150 символов)';
    } else {
        // Дополнительная проверка на XSS
        $data['full_name'] = strip_tags($data['full_name']);
    }

    // Телефон
    if (
        empty($data['phone']) ||
        !preg_match('/^[0-9+\-\s()]{5,30}$/', $data['phone'])
    ) {
        $errors['phone'] = 'Допустимы цифры, +, -, пробелы и скобки';
    }

    // Email
    if (
        empty($data['email']) ||
        !filter_var($data['email'], FILTER_VALIDATE_EMAIL)
    ) {
        $errors['email'] = 'Введите корректный email';
    }

    // Дата рождения
    if (empty($data['birth_date'])) {
        $errors['birth_date'] = 'Укажите дату рождения';
    } elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $data['birth_date'])) {
        $errors['birth_date'] = 'Неверный формат даты';
    }

    // Пол
    if (!in_array($data['gender'] ?? '', ['male', 'female'])) {
        $errors['gender'] = 'Выберите пол';
    }

    // Языки
    if (empty($data['languages'])) {
        $errors['languages'] = 'Выберите хотя бы один язык';
    } else {
        // Проверяем, что все ID языков - целые числа
        $data['languages'] = array_filter($data['languages'], function($id) {
            return is_numeric($id) && $id > 0;
        });
    }

    // Биография
    if (!empty($data['biography'])) {
        $data['biography'] = strip_tags($data['biography'], '<p><br>');
        
        if (!preg_match('/^[а-яА-Яa-zA-Z0-9\s.,!?()\-:;"\n\r]+$/u', $data['biography'])) {
            $errors['biography'] = 'Биография содержит недопустимые символы';
        }
    }

    // Согласие
    if (empty($data['agreement'])) {
        $errors['agreement'] = 'Необходимо согласиться с контрактом';
    }

    return $errors;
}

/**
 * Обновление данных пользователя
 */
function updateUserData($pdo, $userId, $data) {
    try {
        $stmt = $pdo->prepare("
            UPDATE applications 
            SET full_name = :full_name, 
                phone = :phone, 
                email = :email, 
                birth_date = :birth_date, 
                gender = :gender, 
                biography = :biography, 
                agreement = :agreement 
            WHERE id = :id
        ");
        
        $stmt->execute([
            'full_name' => $data['full_name'],
            'phone' => $data['phone'],
            'email' => $data['email'],
            'birth_date' => $data['birth_date'],
            'gender' => $data['gender'],
            'biography' => $data['biography'],
            'agreement' => $data['agreement'] ? 1 : 0,
            'id' => $userId
        ]);
        
        // Обновляем языки
        $stmt = $pdo->prepare("DELETE FROM application_language WHERE application_id = :app_id");
        $stmt->execute(['app_id' => $userId]);
        
        $stmt = $pdo->prepare("INSERT INTO application_language (application_id, language_id) VALUES (:app_id, :lang_id)");
        foreach ($data['languages'] as $languageId) {
            $stmt->execute([
                'app_id' => $userId,
                'lang_id' => $languageId
            ]);
        }
        
        return true;
    } catch (PDOException $e) {
        error_log('Update user error: ' . $e->getMessage());
        throw $e;
    }
}

/**
 * Создание нового пользователя
 */
function createUser($pdo, $data) {
    try {
        $login = 'user_' . random_int(1000, 9999);
        $password = bin2hex(random_bytes(4));
        $passwordHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        
        $stmt = $pdo->prepare("
            INSERT INTO applications 
            (full_name, phone, email, birth_date, gender, biography, agreement, login, password_hash)
            VALUES 
            (:full_name, :phone, :email, :birth_date, :gender, :biography, :agreement, :login, :password_hash)
        ");
        
        $stmt->execute([
            'full_name' => $data['full_name'],
            'phone' => $data['phone'],
            'email' => $data['email'],
            'birth_date' => $data['birth_date'],
            'gender' => $data['gender'],
            'biography' => $data['biography'],
            'agreement' => $data['agreement'] ? 1 : 0,
            'login' => $login,
            'password_hash' => $passwordHash
        ]);
        
        $applicationId = $pdo->lastInsertId();
        
        $stmt = $pdo->prepare("INSERT INTO application_language (application_id, language_id) VALUES (:app_id, :lang_id)");
        foreach ($data['languages'] as $languageId) {
            $stmt->execute([
                'app_id' => $applicationId,
                'lang_id' => $languageId
            ]);
        }
        
        return [
            'login' => $login,
            'password' => $password
        ];
    } catch (PDOException $e) {
        error_log('Create user error: ' . $e->getMessage());
        throw $e;
    }
}

/**
 * Получение статистики по языкам
 */
function getLanguageStats($pdo) {
    try {
        $stmt = $pdo->prepare("
            SELECT l.title, COUNT(al.application_id) as count
            FROM languages l
            LEFT JOIN application_language al ON l.id = al.language_id
            GROUP BY l.id, l.title
            ORDER BY count DESC, l.title
        ");
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log('Get stats error: ' . $e->getMessage());
        return [];
    }
}

/**
 * Получение всех заявок
 */
function getAllApplications($pdo) {
    try {
        $stmt = $pdo->prepare("
            SELECT a.*, GROUP_CONCAT(l.title SEPARATOR ', ') AS languages
            FROM applications a
            LEFT JOIN application_language al ON a.id = al.application_id
            LEFT JOIN languages l ON al.language_id = l.id
            GROUP BY a.id
            ORDER BY a.id DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log('Get applications error: ' . $e->getMessage());
        return [];
    }
}

/**
 * Получение заявки по ID
 */
function getApplicationById($pdo, $id) {
    try {
        $stmt = $pdo->prepare("
            SELECT a.*, GROUP_CONCAT(l.title SEPARATOR ', ') AS languages
            FROM applications a
            LEFT JOIN application_language al ON a.id = al.application_id
            LEFT JOIN languages l ON al.language_id = l.id
            WHERE a.id = :id
            GROUP BY a.id
        ");
        $stmt->execute(['id' => (int)$id]);
        return $stmt->fetch();
    } catch (PDOException $e) {
        error_log('Get application error: ' . $e->getMessage());
        return null;
    }
}

/**
 * Удаление заявки
 */
function deleteApplication($pdo, $id) {
    try {
        $stmt = $pdo->prepare("DELETE FROM applications WHERE id = :id");
        $stmt->execute(['id' => (int)$id]);
        return $stmt->rowCount() > 0;
    } catch (PDOException $e) {
        error_log('Delete application error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Проверка авторизации администратора
 */
function checkAdminAuth() {
    if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW'])) {
        header('WWW-Authenticate: Basic realm="Admin Panel"');
        header('HTTP/1.0 401 Unauthorized');
        die('Требуется авторизация администратора');
    }
    
    require_once 'db.php';
    $pdo = getDatabase();
    
    try {
        $admin = fetchOne("SELECT * FROM admins WHERE login = :login", [
            'login' => $_SERVER['PHP_AUTH_USER']
        ]);
        
        if (!$admin || !password_verify($_SERVER['PHP_AUTH_PW'], $admin['password_hash'])) {
            logSecurityEvent('admin_auth_failed', ['login' => $_SERVER['PHP_AUTH_USER']]);
            header('WWW-Authenticate: Basic realm="Admin Panel"');
            header('HTTP/1.0 401 Unauthorized');
            die('Неверный логин или пароль администратора');
        }
        
        logSecurityEvent('admin_auth_success', ['login' => $_SERVER['PHP_AUTH_USER']]);
        return true;
        
    } catch (PDOException $e) {
        error_log('Admin auth error: ' . $e->getMessage());
        die('Ошибка авторизации');
    }
}