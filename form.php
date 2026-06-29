<?php
// Убедимся что переменные инициализированы
if (!isset($csrfToken)) {
    $csrfToken = generateCsrfToken();
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Лабораторная работа №7</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="card">
        <h1>
            <?php if (isset($_SESSION['user_id'])): ?>
                Редактирование анкеты
            <?php else: ?>
                Анкета пользователя
            <?php endif; ?>
        </h1>
        
        <p class="author">
            Проект выполнила: Рыбалко Евгения
        </p>

        <!-- УСПЕШНО -->
        <?php if (!empty($successMessage)): ?>
            <div class="success">
                <?= safeHtml($successMessage) ?>
            </div>
        <?php endif; ?>

        <!-- ЛОГИН И ПАРОЛЬ -->
        <?php if (!empty($generatedLogin)): ?>
            <div class="credentials">
                <h3>Ваши данные для входа</h3>
                <p><strong>Логин:</strong> <?= safeHtml($generatedLogin) ?></p>
                <p><strong>Пароль:</strong> <?= safeHtml($generatedPassword) ?></p>
                <p class="hint">
                    Сохраните логин и пароль. Они показываются только один раз.
                </p>
            </div>
        <?php endif; ?>

        <!-- ВХОД / ВЫХОД -->
        <div class="auth-links">
            <?php if (isset($_SESSION['user_id'])): ?>
                <a href="logout.php" class="auth-link">Выйти из аккаунта</a>
            <?php else: ?>
                <a href="login.php" class="auth-link">Войти в аккаунт</a>
            <?php endif; ?>
        </div>

        <!-- ФОРМА -->
        <form action="submit.php" method="POST" id="applicationForm">
            <!-- CSRF Токен -->
            <input type="hidden" name="csrf_token" value="<?= safeHtml($csrfToken) ?>">
            
            <!-- ФИО -->
            <div class="form-group">
                <label for="full_name">ФИО</label>
                <input 
                    type="text" 
                    id="full_name"
                    name="full_name"
                    value="<?= safeHtml($values['full_name'] ?? '') ?>"
                    class="<?= isset($errors['full_name']) ? 'error' : '' ?>"
                    maxlength="150"
                    pattern="[а-яА-Яa-zA-Z\s\-]+"
                    required
                >
                <?php if (isset($errors['full_name'])): ?>
                    <div class="message"><?= safeHtml($errors['full_name']) ?></div>
                <?php endif; ?>
            </div>

            <!-- ТЕЛЕФОН -->
            <div class="form-group">
                <label for="phone">Телефон</label>
                <input 
                    type="tel" 
                    id="phone"
                    name="phone"
                    value="<?= safeHtml($values['phone'] ?? '') ?>"
                    class="<?= isset($errors['phone']) ? 'error' : '' ?>"
                    maxlength="30"
                    pattern="[0-9+\-\s()]+"
                    required
                >
                <?php if (isset($errors['phone'])): ?>
                    <div class="message"><?= safeHtml($errors['phone']) ?></div>
                <?php endif; ?>
            </div>

            <!-- EMAIL -->
            <div class="form-group">
                <label for="email">Email</label>
                <input 
                    type="email" 
                    id="email"
                    name="email"
                    value="<?= safeHtml($values['email'] ?? '') ?>"
                    class="<?= isset($errors['email']) ? 'error' : '' ?>"
                    maxlength="120"
                    required
                >
                <?php if (isset($errors['email'])): ?>
                    <div class="message"><?= safeHtml($errors['email']) ?></div>
                <?php endif; ?>
            </div>

            <!-- ДАТА -->
            <div class="form-group">
                <label for="birth_date">Дата рождения</label>
                <input 
                    type="date" 
                    id="birth_date"
                    name="birth_date"
                    value="<?= safeHtml($values['birth_date'] ?? '') ?>"
                    class="<?= isset($errors['birth_date']) ? 'error' : '' ?>"
                    required
                >
                <?php if (isset($errors['birth_date'])): ?>
                    <div class="message"><?= safeHtml($errors['birth_date']) ?></div>
                <?php endif; ?>
            </div>

            <!-- ПОЛ -->
            <div class="form-group">
                <label>Пол</label>
                <div class="radio-group">
                    <label>
                        <input 
                            type="radio" 
                            name="gender" 
                            value="male"
                            <?= ($values['gender'] ?? '') === 'male' ? 'checked' : '' ?>
                            required
                        >
                        Мужской
                    </label>
                    <label>
                        <input 
                            type="radio" 
                            name="gender" 
                            value="female"
                            <?= ($values['gender'] ?? '') === 'female' ? 'checked' : '' ?>
                        >
                        Женский
                    </label>
                </div>
                <?php if (isset($errors['gender'])): ?>
                    <div class="message"><?= safeHtml($errors['gender']) ?></div>
                <?php endif; ?>
            </div>

            <!-- ЯЗЫКИ -->
            <div class="form-group">
                <label for="languages">Любимые языки программирования</label>
                <select name="languages[]" id="languages" multiple required>
                    <?php foreach ($languages as $language): ?>
                        <option 
                            value="<?= safeHtml($language['id']) ?>"
                            <?= in_array($language['id'], $selectedLanguages) ? 'selected' : '' ?>
                        >
                            <?= safeHtml($language['title']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <?php if (isset($errors['languages'])): ?>
                    <div class="message"><?= safeHtml($errors['languages']) ?></div>
                <?php endif; ?>
            </div>

            <!-- БИО -->
            <div class="form-group">
                <label for="biography">Биография</label>
                <textarea 
                    id="biography"
                    name="biography" 
                    rows="5"
                    class="<?= isset($errors['biography']) ? 'error' : '' ?>"
                ><?= safeHtml($values['biography'] ?? '') ?></textarea>
                <?php if (isset($errors['biography'])): ?>
                    <div class="message"><?= safeHtml($errors['biography']) ?></div>
                <?php endif; ?>
            </div>

            <!-- СОГЛАСИЕ -->
            <div class="form-group">
                <label class="checkbox">
                    <input 
                        type="checkbox" 
                        name="agreement"
                        value="1"
                        <?= !empty($values['agreement']) ? 'checked' : '' ?>
                        required
                    >
                    С контрактом ознакомлен(а)
                </label>
                <?php if (isset($errors['agreement'])): ?>
                    <div class="message"><?= safeHtml($errors['agreement']) ?></div>
                <?php endif; ?>
            </div>

            <button type="submit">
                <?php if (isset($_SESSION['user_id'])): ?>
                    Сохранить изменения
                <?php else: ?>
                    Сохранить
                <?php endif; ?>
            </button>
        </form>

        <div class="bottom-link">
            <a href="view.php">Просмотреть заявки</a>
        </div>
    </div>
</body>
</html>