# INSTRUCCIONES: CÓMO CONECTAR LA BASE DE DATOS EN HOSTINGER Y VERCEL

Esta guía te explica paso a paso cómo conectar la base de datos MySQL en Hostinger y asegurar que los récords de **ships.exe** queden guardados de forma 100% permanente.

---

## PARTE 1: CREAR LA BASE DE DATOS EN HOSTINGER

1. Entra a tu panel de control de **Hostinger (hPanel)**.
2. Ve a la sección **Bases de datos** -> **Bases de datos MySQL**.
3. Crea una nueva base de datos completando:
   - **Nombre de la base de datos**: ej. `arc_db` (Hostinger le pondrá un prefijo, quedando algo como `u123456789_arc_db`).
   - **Nombre de usuario de MySQL**: ej. `arc_user` (quedará como `u123456789_arc_user`).
   - **Contraseña**: Escribe una contraseña segura y guárdala.
4. Haz clic en **Crear**.

---

## PARTE 2: CREAR LAS TABLAS (IMPORTAR SQL)

1. En la misma pantalla de bases de datos de Hostinger, busca la base de datos que acabas de crear y haz clic en el botón **Ingresar a phpMyAdmin**.
2. Una vez dentro de phpMyAdmin, haz clic en la pestaña **SQL** (arriba en el menú).
3. Abre el archivo de tu proyecto [`sql/schema.sql`](file:///c:/Users/BFFF/Pictures/proyecto/sql/schema.sql) o copia este código:

```sql
CREATE TABLE IF NOT EXISTS `leaderboard_alltime` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(20) NOT NULL,
  `wallet` VARCHAR(66) NOT NULL,
  `score` BIGINT NOT NULL DEFAULT 0,
  `round` INT NOT NULL DEFAULT 1,
  `date` VARCHAR(30) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `idx_pilot_name` (`name`),
  KEY `idx_score_alltime` (`score` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `leaderboard_weekly` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `week_epoch` BIGINT NOT NULL DEFAULT 0,
  `name` VARCHAR(20) NOT NULL,
  `wallet` VARCHAR(66) NOT NULL,
  `score` BIGINT NOT NULL DEFAULT 0,
  `round` INT NOT NULL DEFAULT 1,
  `date` VARCHAR(30) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY `idx_weekly_pilot` (`week_epoch`, `name`),
  KEY `idx_score_weekly` (`score` DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

4. Pégalo en la caja de texto y haz clic en **Continuar** (o **Go**).
5. Verás un mensaje verde indicando que las 2 tablas se crearon correctamente.

---

## PARTE 3: CONFIGURAR TUS CREDENCIALES EN EL PROYECTO

1. Abre el archivo [`api/db_config.php`](file:///c:/Users/BFFF/Pictures/proyecto/api/db_config.php).
2. Pon tus datos reales de Hostinger y activa `'DB_ENABLED' => true`:

```php
return [
    'DB_ENABLED' => true,
    'DB_HOST'    => 'localhost',
    'DB_PORT'    => '3306',
    'DB_NAME'    => 'u123456789_arc_db',      // El nombre completo que te dio Hostinger
    'DB_USER'    => 'u123456789_arc_user',    // El usuario completo que te dio Hostinger
    'DB_PASS'    => 'TuPasswordSeguroAqui',   // La contraseña que pusiste
    'DB_CHARSET' => 'utf8mb4'
];
```


¡Listo! Con estos pasos tus records de los 7 días y de todos los tiempos quedarán guardados permanentemente en tu base de datos.
