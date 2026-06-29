<?php
/**
 * Подключение к базе данных с защитой от SQL Injection
 */

if (!function_exists('getDatabase')) {
    function getDatabase() {
        static $pdo = null;

        if ($pdo === null) {
            $host = 'localhost';
            $dbname = 'u82673';
            $user = 'u82673';
            $password = '4038561';

            try {
                $pdo = new PDO(
                    "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
                    $user,
                    $password,
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_EMULATE_PREPARES => false, // Важно для защиты от SQL Injection
                        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
                    ]
                );
                
                // Установка дополнительных параметров безопасности MySQL
                $pdo->exec("SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_AUTO_CREATE_USER'");
                
            } catch (PDOException $e) {
                // Не показываем детали ошибки пользователю
                error_log('Database connection error: ' . $e->getMessage());
                die('Ошибка подключения к базе данных. Пожалуйста, попробуйте позже.');
            }
        }

        return $pdo;
    }
}

/**
 * Безопасное выполнение запроса с параметрами
 */
function safeQuery($sql, $params = []) {
    try {
        $pdo = getDatabase();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    } catch (PDOException $e) {
        error_log('Query error: ' . $e->getMessage());
        throw $e;
    }
}

/**
 * Получение одной записи
 */
function fetchOne($sql, $params = []) {
    return safeQuery($sql, $params)->fetch();
}

/**
 * Получение всех записей
 */
function fetchAll($sql, $params = []) {
    return safeQuery($sql, $params)->fetchAll();
}