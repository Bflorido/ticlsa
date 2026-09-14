<?php
/**
 * ARCSYSTEMS XP — DATABASE CONFIGURATION
 * Configuración de conexión a la base de datos (Hostinger / MySQL / MariaDB)
 * 
 * INSTRUCCIONES:
 * 1. Completa tus datos de conexión creados en el panel de Hostinger.
 * 2. Si dejas 'DB_ENABLED' en false, el sistema seguirá funcionando con JSON local como respaldo.
 * 3. Al poner 'DB_ENABLED' en true, todos los records se guardarán y leerán directamente de MySQL.
 */

return [
    // Cambia a true una vez hayas puesto tus credenciales y creado las tablas
    'DB_ENABLED' => false,

    // Datos de conexión de tu base de datos MySQL en Hostinger
    'DB_HOST'    => 'localhost',              // Generalmente 'localhost' en Hostinger
    'DB_PORT'    => '3306',                   // Puerto estándar MySQL
    'DB_NAME'    => 'u123456789_arc_database',// Nombre completo de la BD creada en Hostinger
    'DB_USER'    => 'u123456789_arc_user',    // Usuario de la BD creado en Hostinger
    'DB_PASS'    => 'TuPasswordSeguroAqui',   // Contraseña del usuario de la BD
    'DB_CHARSET' => 'utf8mb4'
];
