# Watcher decide (Phase 3)

```php
$payload = json_encode([
  'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
  'action' => 'checkout', // browse|login|checkout|admin
  'idempotency_key' => bin2hex(random_bytes(8)),
]);
$ch = curl_init(rtrim($watcherBase, '/') . '/api/v1/decide');
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_HTTPHEADER => [
    'Authorization: Bearer ' . $apiKey,
    'Content-Type: application/json',
  ],
  CURLOPT_POSTFIELDS => $payload,
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_TIMEOUT_MS => 400,
]);
$raw = curl_exec($ch);
if ($raw === false) {
  // fail-open for checkout/browse
  return 'allow';
}
$data = json_decode($raw, true);
return $data['outcome'] ?? 'allow';
```
