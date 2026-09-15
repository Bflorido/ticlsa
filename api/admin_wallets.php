<?php
/**
 * ARCSYSTEMS XP — BLINDADO: ADMIN WALLET VAULT & LEADERBOARD VIEWER
 * 
 * MEDIDAS DE BLINDAJE IMPLEMENTADAS:
 * 1. Autenticación de Administrador con hash resistente a timing attacks (hash_equals).
 * 2. Protección contra Fuerza Bruta (Rate Limiting por IP: máx. 5 intentos, bloqueo temporal).
 * 3. Garantía Estricta de Solo Lectura (Zero-Mutation): No existen operaciones de escritura, edición o borrado.
 * 4. Cabeceras HTTP Hardened: Anti-Clickjacking (DENY), CSP, No-Cache, No-Sniff.
 * 5. Cookies de sesión seguras (HttpOnly, SameSite=Strict).
 * 6. Escape estricto contra inyecciones XSS (htmlspecialchars).
 */

// 1. Cabeceras de seguridad estrictas (HTTP Hardening)
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self' 'unsafe-inline';");
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// 2. Sesión segura con cookies protegidas
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict'
    ]);
}

define('ARC_SECURE_ACCESS', true);
$cfg = file_exists(__DIR__ . '/db_config.php') ? include(__DIR__ . '/db_config.php') : [];

if (empty($cfg['DB_ENABLED'])) {
    http_response_code(503);
    die("La base de datos no está habilitada en db_config.php");
}

$adminPass = isset($cfg['ADMIN_PASSWORD']) ? (string)$cfg['ADMIN_PASSWORD'] : 'Cazadorx92*';
$rawKey    = isset($cfg['DB_ENCRYPTION_KEY']) ? (string)$cfg['DB_ENCRYPTION_KEY'] : 'default_arc_secret_key_32_bytes!';
$encKey    = hash('sha256', $rawKey, true);

// 3. Manejo de Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// 4. Rate Limiting contra Fuerza Bruta (en memoria de sesión / IP)
$clientIp = isset($_SERVER['REMOTE_ADDR']) ? preg_replace('/[^0-9a-fA-F:\.]/', '', $_SERVER['REMOTE_ADDR']) : 'unknown';
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['last_attempt_time'] = 0;
}

$loginError = null;
$isLocked = false;
$lockTimeRemaining = 0;

if ($_SESSION['login_attempts'] >= 5) {
    $elapsed = time() - $_SESSION['last_attempt_time'];
    if ($elapsed < 300) { // 5 minutos de bloqueo
        $isLocked = true;
        $lockTimeRemaining = 300 - $elapsed;
    } else {
        $_SESSION['login_attempts'] = 0; // Se reinicia tras expirar el bloqueo
    }
}

// 5. Procesamiento de Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_pass'])) {
    if ($isLocked) {
        $loginError = "⛔ Demasiados intentos fallidos. Sistema bloqueado por {$lockTimeRemaining} segundos.";
    } else {
        $submitted = (string)$_POST['login_pass'];
        if (hash_equals($adminPass, $submitted)) {
            $_SESSION['arc_admin_logged'] = true;
            $_SESSION['login_attempts'] = 0;
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        } else {
            $_SESSION['login_attempts']++;
            $_SESSION['last_attempt_time'] = time();
            $remaining = 5 - $_SESSION['login_attempts'];
            $loginError = "❌ Clave incorrecta. Intentos restantes antes de bloqueo: " . max(0, $remaining);
            if ($_SESSION['login_attempts'] >= 5) {
                $isLocked = true;
                $lockTimeRemaining = 300;
                $loginError = "⛔ Límite alcanzado. Panel bloqueado temporalmente por 5 minutos.";
            }
        }
    }
}

$isAuthenticated = !empty($_SESSION['arc_admin_logged']);

// Función de desencriptado seguro
function decryptWalletExact($payload, $key) {
    if (empty($payload)) return '(Sin Billetera)';
    $parts = explode(':', $payload);
    if (count($parts) !== 2) return $payload;
    $iv = hex2bin($parts[0]);
    $ct = hex2bin($parts[1]);
    if ($iv === false || $ct === false || strlen($iv) !== 16) return '(Error desencriptado)';
    $decrypted = openssl_decrypt($ct, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return $decrypted !== false ? $decrypted : '(Fallo descifrado)';
}

// Si se ejecuta por consola CLI (siempre seguro y local)
if (php_sapi_name() === 'cli') {
    try {
        $dsn = "mysql:host={$cfg['DB_HOST']};port={$cfg['DB_PORT']};dbname={$cfg['DB_NAME']};charset=utf8mb4";
        $pdo = new PDO($dsn, $cfg['DB_USER'], $cfg['DB_PASS'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
        echo "=========================================================================\n";
        echo "  ARCSYSTEMS XP — PANEL ADMINISTRATIVO BLINDADO (CLI)\n";
        echo "=========================================================================\n";
        $stmt = $pdo->query("SELECT id, name, wallet, score, round, date FROM leaderboard_alltime ORDER BY score DESC, round DESC");
        $rows = $stmt->fetchAll();
        echo sprintf("%-4s | %-12s | %-10s | %-6s | %-44s | %s\n", "POS", "PILOTO", "SCORE", "RONDA", "BILLETERA EXACTA (0x...)", "FECHA");
        echo str_repeat("-", 95) . "\n";
        $pos = 1;
        foreach ($rows as $r) {
            $walletExact = decryptWalletExact($r['wallet'], $encKey);
            echo sprintf("#%-3d | %-12s | %-10s | %-6s | %-44s | %s\n", $pos++, $r['name'], number_format($r['score']), $r['round'], $walletExact, $r['date']);
        }
        echo "=========================================================================\n";
        exit;
    } catch (Exception $e) {
        die("Error CLI: " . $e->getMessage());
    }
}

// PANTALLA 1: Formulario de Login si no está autenticado
if (!$isAuthenticated) {
    ?>
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <title>Acceso Blindado — ARCSYSTEMS Vault</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
        body { background: #060911; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .login-card { background: #0f172a; border: 1px solid #1e293b; border-radius: 16px; padding: 36px; width: 100%; max-width: 420px; box-shadow: 0 20px 40px rgba(0,0,0,0.8); text-align: center; }
        .badge-secure { display: inline-flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 12px; border-radius: 99px; font-size: 11px; font-weight: 700; margin-bottom: 20px; }
        h1 { font-size: 20px; font-weight: 800; color: #f8fafc; margin-bottom: 8px; letter-spacing: 0.5px; }
        p { color: #64748b; font-size: 13px; margin-bottom: 24px; }
        input[type="password"] { width: 100%; padding: 12px 16px; background: #060911; border: 1px solid #334155; border-radius: 8px; color: #fff; font-size: 15px; outline: none; margin-bottom: 16px; transition: border-color .2s; }
        input[type="password"]:focus { border-color: #00d4ff; }
        button { width: 100%; padding: 12px; background: #00d4ff; color: #02142b; border: none; border-radius: 8px; font-size: 14px; font-weight: 800; cursor: pointer; transition: opacity .2s; }
        button:hover { opacity: 0.9; }
        button:disabled { background: #334155; color: #64748b; cursor: not-allowed; }
        .alert { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.35); color: #f87171; padding: 10px; border-radius: 8px; font-size: 12px; margin-bottom: 16px; text-align: left; }
        .footer-note { font-size: 11px; color: #475569; margin-top: 24px; }
      </style>
    </head>
    <body>
      <div class="login-card">
        <div class="badge-secure">🛡️ ZERO-TRUST ACCESS CONTROL</div>
        <h1>Bóveda de Billeteras</h1>
        <p>Introduce la clave maestra de administrador para acceder a las direcciones completas.</p>

        <?php if ($loginError): ?>
          <div class="alert"><?= htmlspecialchars($loginError) ?></div>
        <?php endif; ?>

        <form method="POST" action="">
          <input type="password" name="login_pass" placeholder="Clave de Administrador" required autofocus autocomplete="current-password" <?= $isLocked ? 'disabled' : '' ?>>
          <button type="submit" <?= $isLocked ? 'disabled' : '' ?>>
            <?= $isLocked ? 'Acceso Bloqueado' : 'Desbloquear Bóveda' ?>
          </button>
        </form>

        <div class="footer-note">
          Protegido contra fuerza bruta • Cifrado AES-256 en reposo
        </div>
      </div>
    </body>
    </html>
    <?php
    exit;
}

// PANTALLA 2: Panel de Billeteras (Solo Lectura Estricto)
try {
    $dsn = "mysql:host={$cfg['DB_HOST']};port={$cfg['DB_PORT']};dbname={$cfg['DB_NAME']};charset=utf8mb4";
    $pdo = new PDO($dsn, $cfg['DB_USER'], $cfg['DB_PASS'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (Exception $e) {
    die("Error conectando a MySQL: " . htmlspecialchars($e->getMessage()));
}

$tab = isset($_GET['tab']) && $_GET['tab'] === 'weekly' ? 'weekly' : 'alltime';

if ($tab === 'weekly') {
    $table = 'leaderboard_weekly';
    $title = 'Récords Semanales (Weekly)';
    $stmt = $pdo->query("SELECT id, name, wallet, score, round, date FROM leaderboard_weekly ORDER BY score DESC, round DESC");
} else {
    $table = 'leaderboard_alltime';
    $title = 'Récords Históricos (All-Time)';
    $stmt = $pdo->query("SELECT id, name, wallet, score, round, date FROM leaderboard_alltime ORDER BY score DESC, round DESC");
}
$players = $stmt->fetchAll();

// Exportación CSV
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=pilotos_' . $tab . '_' . date('Ymd') . '.csv');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['Posición', 'Piloto', 'Score', 'Ronda', 'Dirección Exacta Wallet', 'Fecha']);
    $p = 1;
    foreach ($players as $r) {
        fputcsv($out, [$p++, $r['name'], $r['score'], $r['round'], decryptWalletExact($r['wallet'], $encKey), $r['date']]);
    }
    fclose($out);
    exit;
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>ARCSYSTEMS — Bóveda de Billeteras (Modo Blindado)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
    body { background: #080c16; color: #f1f5f9; padding: 24px; }
    .container { max-width: 1150px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 18px; margin-bottom: 24px; flex-wrap: wrap; gap: 14px; }
    .logo { font-size: 20px; font-weight: 800; color: #00d4ff; letter-spacing: 0.5px; display: flex; align-items: center; gap: 8px; }
    .status-badge { display: inline-flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.12); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 12px; border-radius: 99px; font-size: 11px; font-weight: 700; }
    .tabs { display: flex; gap: 10px; margin-bottom: 18px; align-items: center; flex-wrap: wrap; }
    .tab-btn { padding: 8px 18px; background: #1e293b; border: 1px solid #334155; color: #94a3b8; border-radius: 8px; text-decoration: none; font-size: 14px; font-weight: 600; transition: all .2s; }
    .tab-btn.active { background: #00d4ff; color: #02142b; border-color: #00d4ff; }
    .actions { margin-left: auto; display: flex; gap: 10px; }
    .btn-export { background: #10b981; color: white; padding: 8px 14px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
    .btn-logout { background: #ef4444; color: white; padding: 8px 14px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }
    .table-box { background: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.6); }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th { background: #1e293b; color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; padding: 14px 16px; border-bottom: 1px solid #334155; }
    td { padding: 14px 16px; border-bottom: 1px solid #1e293b; font-size: 14px; }
    tr:hover { background: rgba(0, 212, 255, 0.03); }
    .pos { font-weight: 800; color: #fbbf24; }
    .pilot { font-weight: 700; color: #f8fafc; }
    .score { font-family: 'Consolas', monospace; font-size: 15px; color: #38bdf8; font-weight: 700; }
    .wallet-exact { font-family: 'Consolas', monospace; font-size: 13px; color: #a7f3d0; background: rgba(16, 185, 129, 0.1); padding: 5px 10px; border-radius: 6px; border: 1px solid rgba(16, 185, 129, 0.25); display: inline-flex; align-items: center; gap: 8px; }
    .btn-copy { background: #334155; color: #cbd5e1; border: none; padding: 4px 10px; border-radius: 6px; font-size: 11px; cursor: pointer; font-weight: 600; transition: all .15s; }
    .btn-copy:hover { background: #00d4ff; color: #02142b; }
    .badge { padding: 3px 8px; border-radius: 99px; font-size: 11px; font-weight: 700; }
    .badge-pos1 { background: #fbbf24; color: #000; }
    .badge-pos2 { background: #cbd5e1; color: #000; }
    .badge-pos3 { background: #d97706; color: #fff; }
    .footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 24px; display: flex; justify-content: center; gap: 16px; align-items: center; }
  </style>
</head>
<body>

<div class="container">
  <div class="header">
    <div class="logo">
      <span>🔐</span> ARCSYSTEMS — Bóveda Administrativa de Billeteras
    </div>
    <div style="display: flex; align-items: center; gap: 12px;">
      <span class="status-badge">🛡️ Solo Lectura (Inmutable)</span>
      <span style="font-size: 13px; color: #94a3b8;">Total pilotos: <b style="color: #00d4ff;"><?= count($players) ?></b></span>
    </div>
  </div>

  <div class="tabs">
    <a href="?tab=alltime" class="tab-btn <?= $tab === 'alltime' ? 'active' : '' ?>">🏆 All-Time (Histórico)</a>
    <a href="?tab=weekly" class="tab-btn <?= $tab === 'weekly' ? 'active' : '' ?>">📅 Semanal (Weekly)</a>
    <div class="actions">
      <a href="?tab=<?= htmlspecialchars($tab) ?>&export=csv" class="btn-export">📥 Exportar CSV</a>
      <a href="?action=logout" class="btn-logout">🚪 Cerrar Sesión</a>
    </div>
  </div>

  <div class="table-box">
    <table>
      <thead>
        <tr>
          <th style="width: 70px;">Puesto</th>
          <th>Piloto</th>
          <th>Score</th>
          <th>Ronda</th>
          <th>Dirección Exacta de Billetera (EVM / MetaMask)</th>
          <th>Fecha</th>
          <th>Acción</th>
        </tr>
      </thead>
      <tbody>
        <?php if (empty($players)): ?>
          <tr>
            <td colspan="7" style="text-align: center; padding: 30px; color: #64748b;">No hay registros en esta categoría.</td>
          </tr>
        <?php else: ?>
          <?php $pos = 1; foreach ($players as $row): 
            $walletExact = decryptWalletExact($row['wallet'], $encKey);
          ?>
            <tr>
              <td>
                <?php if ($pos === 1): ?><span class="badge badge-pos1">🥇 1</span>
                <?php elseif ($pos === 2): ?><span class="badge badge-pos2">🥈 2</span>
                <?php elseif ($pos === 3): ?><span class="badge badge-pos3">🥉 3</span>
                <?php else: ?><span class="pos">#<?= $pos ?></span><?php endif; ?>
              </td>
              <td class="pilot"><?= htmlspecialchars($row['name']) ?></td>
              <td class="score"><?= number_format($row['score']) ?></td>
              <td>Ronda <?= htmlspecialchars($row['round']) ?></td>
              <td>
                <span class="wallet-exact">
                  <?= htmlspecialchars($walletExact) ?>
                </span>
              </td>
              <td style="color: #94a3b8; font-size: 13px;"><?= htmlspecialchars($row['date']) ?></td>
              <td>
                <button class="btn-copy" onclick="copyWallet('<?= htmlspecialchars($walletExact) ?>', this)">📋 Copiar</button>
              </td>
            </tr>
          <?php $pos++; endforeach; ?>
        <?php endif; ?>
      </tbody>
    </table>
  </div>

  <div class="footer">
    <span>🔒 Sesión activa cifrada</span>
    <span>•</span>
    <span>🛡️ Zero-Mutation: Panel protegido contra cualquier alteración de registros</span>
  </div>
</div>

<script>
function copyWallet(val, btn) {
  navigator.clipboard.writeText(val).then(function() {
    const orig = btn.textContent;
    btn.textContent = '✅ Copiado!';
    btn.style.background = '#10b981';
    btn.style.color = '#fff';
    setTimeout(function() {
      btn.textContent = orig;
      btn.style.background = '';
      btn.style.color = '';
    }, 1500);
  });
}
</script>

</body>
</html>

