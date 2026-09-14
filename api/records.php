<?php
/**
 * ARC NETWORK - GLOBAL LEADERBOARD & RECORDS API (hardened v2)
 * - v2 signature: hash(name|score|round|date|ts|nonce|salt) with anti-replay nonce
 * - Timestamp freshness window (10 min)
 * - Per-IP rate limiting (min interval + daily cap) and unique nonce per IP
 * - Score plausibility ceiling based on round reached
 * - LOCK_EX atomic writes
 * NOTE: records.js (Node) mirrors this logic byte-for-byte; PHP is the
 * production source of truth on the deployed host.
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$dataDir = __DIR__ . '/../data';
if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0777, true);
}

$allTimeFile = $dataDir . '/leaderboard.json';
$weeklyFile = $dataDir . '/weekly.json';
$weeklyEpochFile = $dataDir . '/weekly_epoch.txt';
$rateFile = $dataDir . '/ratelimit.json';

$WEEK_MS = 7 * 24 * 60 * 60 * 1000;
$SEC_SALT = 'ARC_VIRUS_v5_SALT_9973';

// --- Hardening knobs ---
$FRESH_WINDOW_MS = 30 * 60 * 1000;  // signature freshness window (30 min for server/client drift)
$MIN_POST_GAP_MS = 8000;             // min seconds between POSTs per IP
$MAX_POSTS_PER_DAY = 200;            // daily cap per IP
$ABS_SCORE_CAP = 2000000;            // absolute score ceiling
$PER_ROUND_BUDGET = 6000;            // plausible score per round
$ROUND_GRACE = 20000;                // base headroom added to round budget

function computeSig($entry, $salt) {
    $name = isset($entry['name']) ? (string)$entry['name'] : '';
    $score = isset($entry['score']) ? (int)$entry['score'] : 0;
    $round = isset($entry['round']) ? (int)$entry['round'] : 0;
    $date = isset($entry['date']) ? (string)$entry['date'] : '';
    $ts = isset($entry['_ts']) ? (string)$entry['_ts'] : '0';
    $nonce = isset($entry['_n']) ? (string)$entry['_n'] : '';
    $str = $name . '|' . $score . '|' . $round . '|' . $date . '|' . $ts . '|' . $nonce . '|' . $salt;

    $h = 0x811c9dc5;
    $len = strlen($str);
    for ($i = 0; $i < $len; $i++) {
        $h ^= ord($str[$i]);
        $h = ($h * 0x01000193) & 0xFFFFFFFF;
    }
    return dechex($h);
}

function loadJson($file) {
    if (!file_exists($file)) return [];
    $content = @file_get_contents($file);
    if (!$content) return [];
    $data = json_decode($content, true);
    return is_array($data) ? $data : [];
}

function saveJson($file, $data) {
    $dir = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
        @chmod($dir, 0777);
    }
    $res = @file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    return ($res !== false);
}

function checkWeeklyEpoch($weeklyEpochFile, $weeklyFile, $WEEK_MS) {
    $now = round(microtime(true) * 1000);
    $epoch = file_exists($weeklyEpochFile) ? (float)@file_get_contents($weeklyEpochFile) : 0;
    if ($epoch <= 0 || ($now - $epoch) >= $WEEK_MS) {
        $epoch = $now;
        @file_put_contents($weeklyEpochFile, (string)$epoch, LOCK_EX);
        saveJson($weeklyFile, []);
    }
    return $epoch;
}

function deduplicateAndRank($list, $limit = 100) {
    if (!is_array($list)) return [];
    $map = [];
    foreach ($list as $item) {
        if (!isset($item['name']) || !isset($item['score'])) continue;
        $name = strtoupper(trim((string)$item['name']));
        $score = (int)$item['score'];
        $round = isset($item['round']) ? (int)$item['round'] : 1;
        if (!isset($map[$name])) {
            $map[$name] = $item;
        } else {
            $existingScore = (int)$map[$name]['score'];
            $existingRound = isset($map[$name]['round']) ? (int)$map[$name]['round'] : 1;
            if ($score > $existingScore || ($score === $existingScore && $round > $existingRound)) {
                $map[$name] = $item;
            }
        }
    }
    $unique = array_values($map);
    usort($unique, function($a, $b) {
        if ($b['score'] !== $a['score']) {
            return $b['score'] - $a['score'];
        }
        return $b['round'] - $a['round'];
    });
    return array_slice($unique, 0, $limit !== null ? $limit : 100);
}

function updateOrInsert($list, $newEntry, $limit = 100) {
    $clean = is_array($list) ? $list : [];
    $clean[] = $newEntry;
    return deduplicateAndRank($clean, $limit);
}

function clientIp() {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    return preg_replace('/[^0-9a-fA-F:\.]/', '', $ip);
}

function checkRateLimit($rateFile, $nonce, $MIN_POST_GAP_MS, $MAX_POSTS_PER_DAY) {
    $nowMs = round(microtime(true) * 1000);
    $ip = clientIp();
    $rl = loadJson($rateFile);
    if (!is_array($rl)) $rl = [];
    // Garbage-collect stale entries (> 24h)
    foreach ($rl as $k => $v) {
        if (!isset($v['day']) || ($nowMs - $v['day']) > 86400000) unset($rl[$k]);
    }
    $entry = isset($rl[$ip]) ? $rl[$ip] : ['last' => 0, 'count' => 0, 'day' => $nowMs, 'nonces' => []];

    if (($nowMs - $entry['last']) < $MIN_POST_GAP_MS) {
        saveJson($rateFile, $rl);
        return 'Rate limited: too many submissions, wait a few seconds';
    }
    if ($entry['count'] >= $MAX_POSTS_PER_DAY) {
        return 'Rate limited: daily submission cap reached';
    }
    if (in_array($nonce, $entry['nonces'], true)) {
        return 'Replay detected: nonce already used';
    }

    $entry['last'] = $nowMs;
    $entry['count'] = (int)$entry['count'] + 1;
    $entry['nonces'][] = $nonce;
    if (count($entry['nonces']) > 64) $entry['nonces'] = array_slice($entry['nonces'], -64);
    $rl[$ip] = $entry;
    saveJson($rateFile, $rl);
    return null;
}

$dbConfig = file_exists(__DIR__ . '/db_config.php') ? include(__DIR__ . '/db_config.php') : [];
function getDbConnection($cfg) {
    if (empty($cfg['DB_ENABLED'])) return null;
    try {
        $host = isset($cfg['DB_HOST']) ? $cfg['DB_HOST'] : 'localhost';
        $port = isset($cfg['DB_PORT']) ? $cfg['DB_PORT'] : '3306';
        $name = isset($cfg['DB_NAME']) ? $cfg['DB_NAME'] : '';
        $user = isset($cfg['DB_USER']) ? $cfg['DB_USER'] : '';
        $pass = isset($cfg['DB_PASS']) ? $cfg['DB_PASS'] : '';
        $charset = isset($cfg['DB_CHARSET']) ? $cfg['DB_CHARSET'] : 'utf8mb4';
        $dsn = "mysql:host={$host};port={$port};dbname={$name};charset={$charset}";
        $opt = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ];
        return new PDO($dsn, $user, $pass, $opt);
    } catch (Exception $e) {
        return null;
    }
}

$pdo = getDbConnection($dbConfig);

checkWeeklyEpoch($weeklyEpochFile, $weeklyFile, $WEEK_MS);

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if ($pdo) {
        try {
            $stmtAll = $pdo->query("SELECT name, wallet, score, round, date FROM leaderboard_alltime ORDER BY score DESC, round DESC LIMIT 50");
            $allTime = $stmtAll->fetchAll();

            $currentEpoch = loadJson($weeklyEpochFile);
            $epochVal = is_numeric($currentEpoch) ? (int)$currentEpoch : 0;
            $stmtWk = $pdo->prepare("SELECT name, wallet, score, round, date FROM leaderboard_weekly WHERE week_epoch >= ? ORDER BY score DESC, round DESC LIMIT 100");
            $stmtWk->execute([$epochVal]);
            $weekly = $stmtWk->fetchAll();

            echo json_encode([
                'success' => true,
                'source'  => 'database',
                'allTime' => $allTime,
                'weekly'  => $weekly
            ]);
            exit;
        } catch (Exception $e) {
            // DB query fail: fallback to json
        }
    }

    $allTime = loadJson($allTimeFile);
    $weekly = loadJson($weeklyFile);
    echo json_encode([
        'success' => true,
        'source'  => 'local',
        'allTime' => $allTime,
        'weekly' => $weekly
    ]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = @file_get_contents('php://input');
    if (strlen($raw) > 8192) {
        http_response_code(413);
        echo json_encode(['error' => 'Payload too large']);
        exit;
    }
    $body = json_decode($raw, true);
    $entry = isset($body['entry']) ? $body['entry'] : null;

    if (!$entry || !isset($entry['name']) || !isset($entry['score']) || !isset($entry['round'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid entry payload']);
        exit;
    }

    $nowMs = round(microtime(true) * 1000);

    $name = strtoupper(substr(preg_replace('/[^A-Za-z0-9 _-]/', '', trim((string)$entry['name'])), 0, 10));
    if (empty($name)) $name = 'PILOT';
    $score = max(0, (int)$entry['score']);
    $round = max(1, min(999, (int)$entry['round']));
    $date = isset($entry['date']) ? substr(strip_tags((string)$entry['date']), 0, 20) : date('m/d/Y');
    $sig = isset($entry['_sig']) ? (string)$entry['_sig'] : '';
    $ts = isset($entry['_ts']) ? (float)$entry['_ts'] : 0;
    $nonce = isset($entry['_n']) ? substr(preg_replace('/[^a-zA-Z0-9]/', '', (string)$entry['_n']), 0, 40) : '';

    // 1. Timestamp freshness (anti pre-computed/replayed signatures)
    if ($ts <= 0 || abs($nowMs - $ts) > $FRESH_WINDOW_MS) {
        http_response_code(403);
        echo json_encode(['error' => 'Stale or invalid timestamp']);
        exit;
    }
    // 2. Nonce required
    if (strlen($nonce) < 8) {
        http_response_code(403);
        echo json_encode(['error' => 'Missing submission nonce']);
        exit;
    }

    $wallet = isset($entry['wallet']) ? trim((string)$entry['wallet']) : '';
    if (!empty($wallet) && !preg_match('/^0x[a-fA-F0-9]{40}$/i', $wallet)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid EVM wallet format']);
        exit;
    }

    $sanitized = [
        'name' => $name,
        'wallet' => $wallet,
        'score' => $score,
        'round' => $round,
        'date' => $date,
        '_ts' => $ts,
        '_n' => $nonce,
        '_sig' => $sig
    ];

    // 3. Signature verification (v2, includes ts + nonce)
    $expectedSig = computeSig($sanitized, $SEC_SALT);
    if (!hash_equals($expectedSig, $sig)) {
        http_response_code(403);
        echo json_encode(['error' => 'Cryptographic signature mismatch']);
        exit;
    }

    // 4. Plausibility: score cannot exceed what a run of $round rounds can yield
    $maxPlausible = min($ABS_SCORE_CAP, $round * $PER_ROUND_BUDGET + $ROUND_GRACE);
    if ($score > $maxPlausible) {
        http_response_code(422);
        echo json_encode(['error' => 'Score exceeds plausible value for the round reached']);
        exit;
    }

    // 5. Rate limiting + nonce uniqueness
    $rlError = checkRateLimit($rateFile, $nonce, $MIN_POST_GAP_MS, $MAX_POSTS_PER_DAY);
    if ($rlError !== null) {
        http_response_code(429);
        echo json_encode(['error' => $rlError]);
        exit;
    }

    if ($pdo) {
        try {
            // Save to All-Time in DB (Insert or Update if higher)
            $sqlAll = "INSERT INTO leaderboard_alltime (name, wallet, score, round, date) 
                       VALUES (:name, :wallet, :score, :round, :date)
                       ON DUPLICATE KEY UPDATE 
                       wallet = VALUES(wallet),
                       score = IF(VALUES(score) > score, VALUES(score), score),
                       round = IF(VALUES(score) > score, VALUES(round), round),
                       date = IF(VALUES(score) > score, VALUES(date), date)";
            $stmtA = $pdo->prepare($sqlAll);
            $stmtA->execute([
                ':name'   => $name,
                ':wallet' => $wallet,
                ':score'  => $score,
                ':round'  => $round,
                ':date'   => $date
            ]);

            // Save to Weekly in DB (Insert or Update if higher for current epoch)
            $currentEpoch = loadJson($weeklyEpochFile);
            $epochVal = is_numeric($currentEpoch) ? (int)$currentEpoch : 0;
            $sqlWk = "INSERT INTO leaderboard_weekly (week_epoch, name, wallet, score, round, date)
                      VALUES (:epoch, :name, :wallet, :score, :round, :date)
                      ON DUPLICATE KEY UPDATE
                      wallet = VALUES(wallet),
                      score = IF(VALUES(score) > score, VALUES(score), score),
                      round = IF(VALUES(score) > score, VALUES(round), round),
                      date = IF(VALUES(score) > score, VALUES(date), date)";
            $stmtW = $pdo->prepare($sqlWk);
            $stmtW->execute([
                ':epoch'  => $epochVal,
                ':name'   => $name,
                ':wallet' => $wallet,
                ':score'  => $score,
                ':round'  => $round,
                ':date'   => $date
            ]);
        } catch (Exception $e) {
            // Log or ignore DB error and fallback to file storage
        }
    }

    $allTime = loadJson($allTimeFile);
    $allTime = updateOrInsert($allTime, $sanitized, 50);
    $s1 = saveJson($allTimeFile, $allTime);

    $weekly = loadJson($weeklyFile);
    $weekly = updateOrInsert($weekly, $sanitized, 100);
    $s2 = saveJson($weeklyFile, $weekly);

    echo json_encode([
        'success' => true,
        'message' => 'Record recorded successfully',
        'source'  => $pdo ? 'database' : 'local',
        'allTime' => $allTime,
        'weekly' => $weekly
    ]);
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'Method not allowed']);
