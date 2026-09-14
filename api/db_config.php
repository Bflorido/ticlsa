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
    // Cambia a true una vez hayas puesto tus credenciales y creado las tablas en MySQL
    'DB_ENABLED' => filter_var(getenv('DB_ENABLED') !== false ? getenv('DB_ENABLED') : false, FILTER_VALIDATE_BOOLEAN),

    // Datos de conexión protegidos (prioriza variables de entorno o valores seguros)
    'DB_HOST'    => getenv('DB_HOST')    ?: 'localhost',
    'DB_PORT'    => getenv('DB_PORT')    ?: '3306',
    'DB_NAME'    => getenv('DB_NAME')    ?: 'u123456789_arc_database',
    'DB_USER'    => getenv('DB_USER')    ?: 'u123456789_arc_user',
    'DB_PASS'    => getenv('DB_PASS')    ?: 'TuPasswordSeguroAqui',
    'DB_CHARSET' => 'utf8mb4',

    // Clave criptográfica para cifrado de wallets en reposo (AES-256-CBC)
    'DB_ENCRYPTION_KEY' => getenv('DB_ENCRYPTION_KEY') ?: 'ARC_CYBER_ENCRYPTION_SECRET_KEY_2026_9973',

    // Forzar conexión cifrada TLS/SSL con MySQL
    'DB_SSL_ENABLED' => true
];
