<?php

namespace BasicXII\CloudSecurity\Scanner;

use RuntimeException;

class RuleUpdates
{
    /** @param array<string, string> $publicKeys */
    public function cached(LocalState $state, array $publicKeys, int $minimumVersion = 0): ?RulePack
    {
        $envelope = $state->read('rules.json');
        if ($envelope === null) {
            if ($minimumVersion > 0) {
                throw new RuntimeException('A verified security rule pack is required by local policy.');
            }

            return null;
        }
        $pack = RulePack::verify($envelope, $publicKeys, time(), true);
        if ($pack->version < $minimumVersion) {
            throw new RuntimeException('Cached security rules are below the local minimum version.');
        }

        return $pack;
    }

    /** @param array<string, mixed> $envelope
     * @param  array<string, string>  $publicKeys
     */
    public function install(LocalState $state, array $envelope, array $publicKeys, int $minimumVersion = 0): RulePack
    {
        $pack = RulePack::verify($envelope, $publicKeys, time());
        $previous = $state->read('rules.json');
        $oldVersion = 0;
        if ($previous !== null) {
            $bytes = is_string($previous['payload'] ?? null) ? base64_decode($previous['payload'], true) : false;
            if ($bytes === false) {
                throw new RuntimeException('Cached security rule state is invalid.');
            }
            $payload = json_decode($bytes, true, 16, JSON_THROW_ON_ERROR);
            if (! is_array($payload) || ! is_int($payload['version'] ?? null)) {
                throw new RuntimeException('Cached security rule version is invalid.');
            }
            $oldVersion = $payload['version'];
            if ($oldVersion === $pack->version && hash('sha256', $bytes) !== $pack->digest) {
                throw new RuntimeException('A rule version cannot be replaced with different contents.');
            }
        }
        if ($pack->version < max($oldVersion, $minimumVersion)) {
            throw new RuntimeException('Security rule rollback rejected.');
        }
        $state->save('rules.json', $envelope);

        return $pack;
    }
}
