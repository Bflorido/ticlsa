-- ==========================================================
-- ARCSYSTEMS XP — SHIPS.EXE LEADERBOARD DATABASE SCHEMA
-- ==========================================================
-- Compatible con:
--   1. MySQL / MariaDB (Hostinger cPanel / phpMyAdmin)
--   2. PostgreSQL (Supabase / Neon / Vercel Postgres)
-- ==========================================================

-- ----------------------------------------------------------
-- 1. SECCIÓN PARA MYSQL / MARIADB (Hostinger / cPanel)
-- Copia y pega esto en la pestaña SQL de phpMyAdmin en Hostinger:
-- ----------------------------------------------------------

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


-- ----------------------------------------------------------
-- 2. SECCIÓN PARA POSTGRESQL (Supabase / Neon / Vercel Postgres)
-- Si usas Supabase o Postgres, ejecuta este bloque en el SQL Editor:
-- ----------------------------------------------------------
/*
CREATE TABLE IF NOT EXISTS leaderboard_alltime (
  id SERIAL PRIMARY KEY,
  name VARCHAR(20) NOT NULL UNIQUE,
  wallet VARCHAR(66) NOT NULL,
  score BIGINT NOT NULL DEFAULT 0,
  round INT NOT NULL DEFAULT 1,
  date VARCHAR(30) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_score_alltime ON leaderboard_alltime(score DESC);

CREATE TABLE IF NOT EXISTS leaderboard_weekly (
  id SERIAL PRIMARY KEY,
  week_epoch BIGINT NOT NULL DEFAULT 0,
  name VARCHAR(20) NOT NULL,
  wallet VARCHAR(66) NOT NULL,
  score BIGINT NOT NULL DEFAULT 0,
  round INT NOT NULL DEFAULT 1,
  date VARCHAR(30) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT uq_weekly_pilot UNIQUE (week_epoch, name)
);

CREATE INDEX IF NOT EXISTS idx_score_weekly ON leaderboard_weekly(score DESC);
*/
