<?php
/**
 * ARCSYSTEMS XP — HARDENED DATABASE CONFIGURATION
 * Configuración de conexión a la base de datos (Hostinger / MySQL / MariaDB)
 * Con soporte para variables de entorno, protección de acceso directo y cifrado.
 */

// 1. Bloquear ejecución directa por HTTP (Zero-Trust)
if (!defined('ARC_SECURE_ACCESS')) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Direct access forbidden.']);
    exit;
}

return [
    // DB habilitada - credenciales y tablas configuradas correctamente
    'DB_ENABLED' => filter_var(getenv('DB_ENABLED') !== false ? getenv('DB_ENABLED') : true, FILTER_VALIDATE_BOOLEAN),

    // Datos de conexión protegidos (prioriza variables de entorno o valores seguros)
    'DB_HOST'    => getenv('DB_HOST')    ?: '127.0.0.1',
    'DB_PORT'    => getenv('DB_PORT')    ?: '3301',
    'DB_NAME'    => getenv('DB_NAME')    ?: 'leaderboard_db',
    'DB_USER'    => getenv('DB_USER')    ?: 'root',
    'DB_PASS'    => getenv('DB_PASS')    ?: 'Cazadorx92*',
    'DB_CHARSET' => 'utf8mb4',

    // Clave criptográfica para cifrado de wallets en reposo (AES-256-CBC)
    'DB_ENCRYPTION_KEY' => getenv('DB_ENCRYPTION_KEY') ?: 'ARC_CYBER_ENCRYPTION_SECRET_KEY_2026_9973',

    // Forzar conexión cifrada TLS/SSL con MySQL
    'DB_SSL_ENABLED' => true,

    // Clave maestra de acceso al panel administrativo de billeteras (admin_wallets.php)
    'ADMIN_PASSWORD' => getenv('ADMIN_PASSWORD') ?: 'Cazadorx92*'
];
