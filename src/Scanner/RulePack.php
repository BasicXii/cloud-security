<?php

namespace BasicXII\CloudSecurity\Scanner;

use RuntimeException;

class RulePack
{
    public const ENGINE = 2;

    public const MAX_BYTES = 32768;

    /** @param array<string, int> $scores */
    private function __construct(
        public readonly int $version,
        public readonly int $expiresAt,
        public readonly array $scores,
        public readonly string $digest,
    ) {}

    /** @param array<string, mixed> $envelope
     * @param  array<string, string>  $publicKeys
     */
    public static function verify(array $envelope, array $publicKeys, int $now, bool $allowExpired = false): self
    {
        self::check(count($envelope) === 3 && array_diff(array_keys($envelope), ['key_id', 'payload', 'signature']) === []);
        self::check(is_string($envelope['key_id']) && preg_match('/^[a-zA-Z0-9_-]{1,40}$/D', $envelope['key_id']) === 1);
        self::check(is_string($envelope['payload']) && strlen($envelope['payload']) <= self::MAX_BYTES
            && is_string($envelope['signature']) && strlen($envelope['signature']) <= 1024);
        $payload = base64_decode($envelope['payload'], true);
        $signature = base64_decode($envelope['signature'], true);
        $pem = $publicKeys[$envelope['key_id']] ?? null;
        self::check(is_string($pem) && str_starts_with($pem, '-----BEGIN PUBLIC KEY-----') && strlen($pem) <= 8192);
        $key = openssl_pkey_get_public($pem);
        if ($key === false || $payload === false || $signature === false) {
            throw new RuntimeException('Security rule pack verification failed.');
        }
        $details = openssl_pkey_get_details($key);
        self::check($details !== false && $details['type'] === OPENSSL_KEYTYPE_RSA && $details['bits'] >= 3072);
        self::check(openssl_verify("basicxii-lens-rules-v1\n".$envelope['key_id']."\n".$envelope['payload'], $signature, $key, OPENSSL_ALGO_SHA256) === 1);
        $data = json_decode($payload, true, 16, JSON_THROW_ON_ERROR);
        self::check(is_array($data) && count($data) === 6 && array_diff(array_keys($data), ['schema', 'version', 'released_at', 'expires_at', 'minimum_engine', 'rules']) === []);
        self::check($data['schema'] === 1 && is_int($data['version']) && $data['version'] >= 1 && $data['version'] <= 2147483647
            && is_int($data['minimum_engine']) && $data['minimum_engine'] >= 1 && $data['minimum_engine'] <= self::ENGINE);
        self::check(is_int($data['released_at']) && is_int($data['expires_at']) && $data['released_at'] > 0
            && $data['released_at'] <= $now + 300 && $data['expires_at'] > $data['released_at']
            && 366 * 86400 >= $data['expires_at'] - $data['released_at'] && ($allowExpired || $data['expires_at'] > $now));
        self::check(is_array($data['rules']) && array_is_list($data['rules']) && count($data['rules']) === count(RiskScorer::SCORES));
        $scores = [];
        foreach ($data['rules'] as $rule) {
            self::check(is_array($rule) && count($rule) === 2 && array_diff(array_keys($rule), ['id', 'score']) === []);
            self::check(is_string($rule['id']) && array_key_exists($rule['id'], RiskScorer::SCORES) && ! isset($scores[$rule['id']])
                && is_int($rule['score']) && $rule['score'] >= 0 && $rule['score'] <= 100);
            $scores[$rule['id']] = $rule['score'];
        }

        return new self($data['version'], $data['expires_at'], $scores, hash('sha256', $payload));
    }

    public function name(): string
    {
        return 'signed-'.$this->version.'-'.substr($this->digest, 0, 12);
    }

    private static function check(bool $condition): void
    {
        if (! $condition) {
            throw new RuntimeException('Security rule pack verification failed.');
        }
    }
}
