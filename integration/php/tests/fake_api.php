<?php
// Router for PHP's built-in web server. It pretends to be the Security API and
// records every request so the tests can inspect exactly what the client sent.
//
// Behaviour is scripted through a JSON control file (path in FAKE_API_CONTROL):
//   { "status": 200, "body": {...} | "raw text", "delay_ms": 0, "fail_first": 0 }
// "fail_first" answers 503 to that many requests before behaving normally.

$controlFile = getenv('FAKE_API_CONTROL');
$logFile     = getenv('FAKE_API_LOG');
$control     = is_file($controlFile) ? (json_decode((string) file_get_contents($controlFile), true) ?: []) : [];

$headers = [];
foreach (getallheaders() as $k => $v) {
    $headers[strtolower($k)] = $v;
}
file_put_contents($logFile, json_encode([
    'method'  => $_SERVER['REQUEST_METHOD'],
    'path'    => parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH),
    'headers' => $headers,
    'body'    => file_get_contents('php://input'),
]) . "\n", FILE_APPEND);

if (!empty($control['delay_ms'])) {
    usleep((int) $control['delay_ms'] * 1000);
}

$failFirst = (int) ($control['fail_first'] ?? 0);
if ($failFirst > 0) {
    $control['fail_first'] = $failFirst - 1;
    file_put_contents($controlFile, json_encode($control));
    http_response_code(503);
    echo json_encode(['message' => 'unavailable']);
    return;
}

http_response_code((int) ($control['status'] ?? 200));
$body = $control['body'] ?? ['ok' => true];
if (is_string($body)) {
    echo $body;
} else {
    header('Content-Type: application/json');
    echo json_encode($body);
}
