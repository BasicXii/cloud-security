<?php

namespace BasicXII\CloudSecurity\Scanner;

use RuntimeException;

class LocalState
{
    private string $secret;

    /** @var resource|null */
    private $lock = null;

    public function __construct(private string $directory)
    {
        if (is_link($directory) || (! is_dir($directory) && ! @mkdir($directory, 0700, true))) {
            throw new RuntimeException('Scanner state directory is unavailable.');
        }
        if (is_link($directory.'/scan.lock') || is_link($directory.'/secret')) {
            throw new RuntimeException('Scanner state must not contain symbolic links.');
        }
        $this->lock = @fopen($directory.'/scan.lock', 'c');
        if ($this->lock === false || ! flock($this->lock, LOCK_EX | LOCK_NB)) {
            throw new RuntimeException('Another scan is active or scanner state is unavailable.');
        }
        if (! is_file($directory.'/secret')) {
            if (is_file($directory.'/baseline.json') || $this->pending() !== []) {
                throw new RuntimeException('Baseline secret is missing. Restore local scanner state.');
            }
            $this->write('secret', bin2hex(random_bytes(32)));
        }
        $secret = @file_get_contents($directory.'/secret');
        if (! is_string($secret) || ! preg_match('/^[a-f0-9]{64}$/D', $secret)) {
            throw new RuntimeException('Scanner state secret is invalid.');
        }
        $this->secret = $secret;
    }

    public function __destruct()
    {
        if (is_resource($this->lock)) {
            flock($this->lock, LOCK_UN);
            fclose($this->lock);
        }
    }

    public function identifier(string $path): string
    {
        return hash_hmac('sha256', $path, $this->secret);
    }

    /** @return array<string, mixed>|null */
    public function read(string $name): ?array
    {
        $path = $this->directory.'/'.$name;
        if (! file_exists($path)) {
            return null;
        }
        if (is_link($path) || filesize($path) > 16777216) {
            throw new RuntimeException('Scanner state is invalid or exceeds its size limit.');
        }
        $envelope = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($envelope) || ! is_string($envelope['payload'] ?? null) || ! is_string($envelope['signature'] ?? null)
            || ! hash_equals($this->identifier($envelope['payload']), $envelope['signature'])) {
            throw new RuntimeException('Scanner state authentication failed.');
        }
        $data = json_decode($envelope['payload'], true, 512, JSON_THROW_ON_ERROR);
        if (! is_array($data)) {
            throw new RuntimeException('Scanner state is invalid.');
        }

        return $data;
    }

    /** @param array<string, mixed> $data */
    public function save(string $name, array $data): void
    {
        $payload = json_encode($data, JSON_THROW_ON_ERROR);
        $this->write($name, json_encode(['payload' => $payload, 'signature' => $this->identifier($payload)], JSON_THROW_ON_ERROR));
    }

    /** @return list<string> */
    public function pending(): array
    {
        return array_map('basename', glob($this->directory.'/report-*.json') ?: []);
    }

    public function acknowledge(string $name): void
    {
        if (! @unlink($this->directory.'/'.$name)) {
            throw new RuntimeException('Unable to acknowledge local scan report.');
        }
    }

    private function write(string $name, string $contents): void
    {
        $path = $this->directory.'/'.$name;
        if (is_link($path)) {
            throw new RuntimeException('Scanner state must not contain symbolic links.');
        }
        $temporary = tempnam($this->directory, '.lens-');
        if ($temporary === false) {
            throw new RuntimeException('Unable to write scanner state.');
        }
        @chmod($temporary, 0600);
        try {
            if (file_put_contents($temporary, $contents, LOCK_EX) !== strlen($contents) || ! @rename($temporary, $path)) {
                throw new RuntimeException('Unable to commit scanner state.');
            }
        } finally {
            if (is_file($temporary)) {
                @unlink($temporary);
            }
        }
    }
}
