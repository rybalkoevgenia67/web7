<?php
session_start();
require_once 'functions.php';
require_once 'db.php';
require_once 'security.php';

setSecurityHeaders();

// Проверяем авторизацию администратора
checkAdminAuth();

$pdo = getDatabase();

// Генерируем CSRF токен для форм
$csrfToken = generateCsrfToken();

// Обработка действий администратора
$message = '';
$messageType = '';

// Удаление заявки
if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
    // Проверяем CSRF токен для GET-запросов через специальный параметр
    if (!isset($_GET['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_GET['csrf_token'])) {
        $message = 'Ошибка безопасности: недействительный токен';
        $messageType = 'error';
    } else {
        $id = (int)$_GET['id'];
        if (deleteApplication($pdo, $id)) {
            $message = 'Заявка успешно удалена';
            $messageType = 'success';
            logSecurityEvent('app_deleted', ['id' => $id]);
        } else {
            $message = 'Ошибка при удалении заявки';
            $messageType = 'error';
        }
        // Обновляем токен после действия
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// Редактирование заявки
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_id'])) {
    // Проверяем CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $message = 'Ошибка безопасности: недействительный токен';
        $messageType = 'error';
    } else {
        $errors = validateUserData($_POST);
        
        if (empty($errors)) {
            $id = (int)$_POST['edit_id'];
            updateUserData($pdo, $id, $_POST);
            $message = 'Данные успешно обновлены';
            $messageType = 'success';
            logSecurityEvent('app_updated', ['id' => $id]);
        } else {
            $message = implode('<br>', array_map('safeHtml', $errors));
            $messageType = 'error';
        }
        // Обновляем токен
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

// Получаем данные
$applications = getAllApplications($pdo);
$languageStats = getLanguageStats($pdo);
$editingApp = null;

if (isset($_GET['action']) && $_GET['action'] === 'edit' && isset($_GET['id'])) {
    $editingApp = getApplicationById($pdo, (int)$_GET['id']);
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Панель администратора</title>
    <link rel="stylesheet" href="style.css">
    <style>
        /* ... стили остаются те же ... */
    </style>
</head>
<body>
    <div class="card" style="max-width: 1400px;">
        <div class="admin-header">
            <h1 style="color: white; margin: 0;">Панель администратора</h1>
            <p style="margin: 10px 0 0 0;">Управление заявками и просмотр статистики</p>
        </div>
        
        <?php if ($message): ?>
            <div class="message <?= safeHtml($messageType) ?>">
                <?= $message ?>
            </div>
        <?php endif; ?>
        
        <!-- Статистика -->
        <div class="stats-section">
            <h2 style="color: #b86b82; margin-top: 0;">Статистика по языкам программирования</h2>
            <div class="stats-grid">
                <?php foreach ($languageStats as $stat): ?>
                    <div class="stat-item">
                        <div class="stat-language"><?= safeHtml($stat['title']) ?></div>
                        <div class="stat-count"><?= (int)$stat['count'] ?> чел.</div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        
        <!-- Форма редактирования -->
        <?php if ($editingApp): ?>
            <div class="edit-form">
                <h2>Редактирование заявки #<?= safeHtml($editingApp['id']) ?></h2>
                <form method="POST" action="admin.php">
                    <input type="hidden" name="csrf_token" value="<?= safeHtml($csrfToken) ?>">
                    <input type="hidden" name="edit_id" value="<?= safeHtml($editingApp['id']) ?>">
                    
                    <div class="form-group">
                        <label>ФИО</label>
                        <input type="text" name="full_name" value="<?= safeHtml($editingApp['full_name']) ?>" required maxlength="150">
                    </div>
                    
                    <div class="form-group">
                        <label>Телефон</label>
                        <input type="tel" name="phone" value="<?= safeHtml($editingApp['phone']) ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Email</label>
                        <input type="email" name="email" value="<?= safeHtml($editingApp['email']) ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Дата рождения</label>
                        <input type="date" name="birth_date" value="<?= safeHtml($editingApp['birth_date']) ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label>Пол</label>
                        <div class="radio-group">
                            <label>
                                <input type="radio" name="gender" value="male" <?= $editingApp['gender'] === 'male' ? 'checked' : '' ?>>
                                Мужской
                            </label>
                            <label>
                                <input type="radio" name="gender" value="female" <?= $editingApp['gender'] === 'female' ? 'checked' : '' ?>>
                                Женский
                            </label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label>Любимые языки программирования</label>
                        <select name="languages[]" multiple>
                            <?php
                            $languages = fetchAll("SELECT * FROM languages ORDER BY title");
                            $selectedLanguages = array_column(
                                fetchAll(
                                    "SELECT language_id FROM application_language WHERE application_id = :id",
                                    ['id' => $editingApp['id']]
                                ),
                                'language_id'
                            );
                            
                            foreach ($languages as $language):
                            ?>
                                <option value="<?= safeHtml($language['id']) ?>" <?= in_array($language['id'], $selectedLanguages) ? 'selected' : '' ?>>
                                    <?= safeHtml($language['title']) ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label>Биография</label>
                        <textarea name="biography" rows="5"><?= safeHtml($editingApp['biography']) ?></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label class="checkbox">
                            <input type="checkbox" name="agreement" value="1" <?= $editingApp['agreement'] ? 'checked' : '' ?>>
                            С контрактом ознакомлен(а)
                        </label>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <button type="submit">Сохранить изменения</button>
                        <a href="admin.php" class="cancel-btn">Отмена</a>
                    </div>
                </form>
            </div>
        <?php endif; ?>
        
        <!-- Таблица заявок -->
        <h2 style="color: #b86b82;">Все заявки (<?= count($applications) ?>)</h2>
        
        <div style="overflow-x: auto;">
            <table class="admin-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>ФИО</th>
                        <th>Телефон</th>
                        <th>Email</th>
                        <th>Дата рождения</th>
                        <th>Пол</th>
                        <th>Языки</th>
                        <th>Логин</th>
                        <th>Создано</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($applications)): ?>
                        <tr>
                            <td colspan="10" style="text-align: center; padding: 20px;">Заявок пока нет</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($applications as $app): ?>
                            <tr>
                                <td>#<?= safeHtml($app['id']) ?></td>
                                <td><?= safeHtml($app['full_name']) ?></td>
                                <td><?= safeHtml($app['phone']) ?></td>
                                <td><?= safeHtml($app['email']) ?></td>
                                <td><?= safeHtml($app['birth_date']) ?></td>
                                <td><?= $app['gender'] === 'male' ? 'М' : 'Ж' ?></td>
                                <td><?= safeHtml($app['languages']) ?></td>
                                <td><?= safeHtml($app['login']) ?></td>
                                <td><?= safeHtml($app['created_at']) ?></td>
                                <td>
                                    <a href="admin.php?action=edit&id=<?= urlencode($app['id']) ?>" class="action-btn edit-btn">Ред.</a>
                                    <a href="admin.php?action=delete&id=<?= urlencode($app['id']) ?>&csrf_token=<?= urlencode($csrfToken) ?>" 
                                       class="action-btn delete-btn" 
                                       onclick="return confirm('Удалить заявку #<?= safeHtml($app['id']) ?>?')">Удал.</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        
        <div class="bottom-link" style="margin-top: 30px;">
            <a href="index.php">Вернуться на главную</a>
        </div>
    </div>
</body>
</html>