<?php
declare(strict_types=1);
/**
 * php2shell-lab.php - read-only research probe for the PHP2Shell local lab.
 *
 * Additive: drop into the webroot, delete when finished. No side effects on a
 * status request. A ?mode=oom request deliberately fatals to observe recovery.
 * Token-gated. The token is substituted at deploy time.
 */
const P2S_TOKEN = '__P2S_TOKEN__';

function p2s_bytes(string $v): int
{
    $v = trim($v);
    if ($v === '' || $v === '-1') {
        return -1;
    }
    $unit = strtolower(substr($v, -1));
    $num  = (float) $v;
    switch ($unit) {
        case 'g': return (int) ($num * 1073741824);
        case 'm': return (int) ($num * 1048576);
        case 'k': return (int) ($num * 1024);
        default:  return (int) $num;
    }
}

$token = (string) ($_SERVER['HTTP_X_P2S_TOKEN'] ?? ($_GET['t'] ?? ''));
if (!hash_equals(P2S_TOKEN, $token)) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'token mismatch']);
    exit;
}

header('Cache-Control: no-store');

$mode = (string) ($_GET['mode'] ?? 'status');

if ($mode === 'oom') {
    // Controlled, script-driven OOM. Flush the first line so the client can tell
    // the request was alive before the fatal.
    header('Content-Type: text/plain');
    $limit = (string) ini_get('memory_limit');
    echo 'oom_start pid=', getmypid(),
         ' limit=', $limit,
         ' sapi=', PHP_SAPI, "\n";
    @ob_flush();
    @flush();

    $limitBytes = p2s_bytes($limit);
    $blockMiB   = max(1, (int) ($_GET['block_mib'] ?? 1));
    if ($limitBytes > 0) {
        $blocks = (int) ceil($limitBytes / ($blockMiB * 1048576)) + 6;
    } else {
        $blocks = (int) ($_GET['blocks'] ?? 256);
    }
    $blocks = max(1, min(2048, $blocks));

    $keep = [];
    for ($i = 0; $i < $blocks; $i++) {
        $keep[] = str_repeat('P', $blockMiB * 1048576);
    }
    echo 'oom_survived pid=', getmypid(), ' blocks=', $blocks, "\n";
    exit;
}

$ini = static function (string $k): ?string {
    $v = ini_get($k);
    return $v === false ? null : $v;
};

$payload = [
    'probe'        => 'php2shell-lab',
    'generated_at' => gmdate('c'),
    'php_version'  => PHP_VERSION,
    'php_version_id' => PHP_VERSION_ID,
    'sapi'         => PHP_SAPI,
    'os'           => PHP_OS_FAMILY,
    'arch'         => php_uname('m'),
    'zts'          => (bool) (defined('ZEND_THREAD_SAFE') ? ZEND_THREAD_SAFE : false),
    'pid'          => getmypid(),
    'thread_id'    => function_exists('zend_thread_id') ? zend_thread_id() : null,
    'request_id'   => bin2hex(random_bytes(8)),
    'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? null,
    'ini' => [
        'memory_limit'                      => $ini('memory_limit'),
        'post_max_size'                     => $ini('post_max_size'),
        'upload_max_filesize'               => $ini('upload_max_filesize'),
        'max_file_uploads'                  => $ini('max_file_uploads'),
        'max_input_vars'                    => $ini('max_input_vars'),
        'max_input_nesting_level'           => $ini('max_input_nesting_level'),
        'session.upload_progress.enabled'   => $ini('session.upload_progress.enabled'),
        'session.upload_progress.cleanup'   => $ini('session.upload_progress.cleanup'),
        'session.use_cookies'               => $ini('session.use_cookies'),
        'session.use_strict_mode'           => $ini('session.use_strict_mode'),
        'display_errors'                    => $ini('display_errors'),
        'log_errors'                        => $ini('log_errors'),
        'error_reporting'                   => $ini('error_reporting'),
        'expose_php'                        => $ini('expose_php'),
        'fatal_error_backtraces'            => $ini('fatal_error_backtraces'),
        'opcache.enable'                    => $ini('opcache.enable'),
        'zend.assertions'                   => $ini('zend.assertions'),
    ],
    'extensions' => [
        'session' => extension_loaded('session'),
        'opcache' => extension_loaded('Zend OPcache'),
    ],
];

header('Content-Type: application/json');
header('X-P2S-Worker: ' . getmypid() . ':' . (function_exists('zend_thread_id') ? zend_thread_id() : '0'));
echo json_encode($payload, JSON_PRETTY_PRINT | JSON_PARTIAL_OUTPUT_ON_ERROR);