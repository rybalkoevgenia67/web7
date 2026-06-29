<?php
session_start();
require_once 'db.php';
require_once 'security.php';

setSecurityHeaders();

$pdo = getDatabase();

// Используем безопасные запросы
$applications = getAllApplications($pdo);
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Сохраненные заявки</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="card big-card">
        <h1>Сохраненные заявки</h1>
        <p class="author">Проект выполнила: Рыбалко Евгения</p>
        
        <?php if (empty($applications)): ?>
            <p>Пока заявок нет</p>
        <?php else: ?>
            <div class="applications-grid">
                <?php foreach ($applications as $app): ?>
                    <div class="application-item">
                        <div class="app-id">#<?= safeHtml($app['id']) ?></div>
                        <h3><?= safeHtml($app['full_name']) ?></h3>
                        
                        <p><strong>Телефон:</strong> <?= safeHtml($app['phone']) ?></p>
                        <p><strong>Email:</strong> <?= safeHtml($app['email']) ?></p>
                        <p><strong>Дата рождения:</strong> <?= safeHtml($app['birth_date']) ?></p>
                        <p><strong>Пол:</strong> <?= $app['gender'] === 'male' ? 'Мужской' : 'Женский' ?></p>
                        <p><strong>Языки:</strong> <?= safeHtml($app['languages']) ?></p>
                        
                        <p><strong>Биография:</strong><br>
                            <?= nl2br(safeHtml($app['biography'])) ?></p>
                        
                        <p><strong>Согласие:</strong> <?= $app['agreement'] ? 'Да' : 'Нет' ?></p>
                        <div class="date"><?= safeHtml($app['created_at']) ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        
        <div class="bottom-link">
            <a href="index.php">Вернуться к форме</a>
        </div>
    </div>
</body>
</html>