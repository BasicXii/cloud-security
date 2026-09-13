<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Scanner\LocalScanner;
use BasicXII\CloudSecurity\Scanner\LocalState;
use BasicXII\CloudSecurity\Scanner\Quarantine;
use BasicXII\CloudSecurity\Scanner\RuleUpdates;
use Illuminate\Console\Command;
use RuntimeException;
use Throwable;

class PollSecurity extends Command
{
    protected $signature = 'lens:poll';

    protected $description = 'Synchronize metadata and execute one approved security command without a shell';

    public function handle(CloudSecurityClient $client, LocalScanner $scanner, RuleUpdates $rules, Quarantine $quarantine): int
    {
        if (! config('cloud-security.scanner.commands_enabled', false)) {
            $this->warn('Security polling is disabled locally. Set LENS_SECURITY_COMMANDS_ENABLED=true.');

            return self::FAILURE;
        }
        try {
            $instance = (string) config('cloud-security.agent.instance', 'default');
            $state = new LocalState(storage_path('basicxii-lens/'.hash('sha256', config('cloud-security.project_id').'|'.$instance)));
            $receipt = $state->read('command-receipt.json');
            if (($receipt['result'] ?? null) === 'started') {
                $receipt['result'] = 'interrupted';
                $state->save('command-receipt.json', $receipt);
            }
            $response = $client->securityPoll($instance, $receipt);
            if (($response['accepted'] ?? false) !== true) {
                throw new RuntimeException('Missing command acknowledgement.');
            }
            if ($receipt !== null) {
                $state->acknowledge('command-receipt.json');
            }
            $command = $response['command'] ?? null;
            if ($command !== null) {
                $this->validateCommand($command);
                $receipt = ['id' => $command['id'], 'result' => 'started'];
                $state->save('command-receipt.json', $receipt);
                $result = 'rejected';
                if ($command['expires_at'] > time()) {
                    try {
                        $result = $this->performCommand($command, $state, $client, $scanner, $rules, $quarantine, $instance);
                    } catch (Throwable) {
                        $result = 'failed';
                    }
                }
                $state->save('command-receipt.json', ['id' => $command['id'], 'result' => $result]);
                $this->info('Security command '.$result.'. Receipt will synchronize on the next poll.');
            }
            foreach ($state->pending() as $name) {
                $report = $state->read($name);
                if ($report === null || ($client->scan($report)['accepted'] ?? false) !== true) {
                    throw new RuntimeException('Missing scan acknowledgement.');
                }
                $state->acknowledge($name);
            }

            return self::SUCCESS;
        } catch (Throwable) {
            $this->error('Security polling failed. Local metadata and receipts were retained; retry lens:poll.');

            return self::FAILURE;
        }
    }

    /** @param array<string, mixed> $command */
    private function validateCommand(array $command): void
    {
        if (array_diff(array_keys($command), ['id', 'type', 'payload', 'expires_at']) !== []
            || ! is_string($command['id'] ?? null) || ! preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/Di', $command['id'])
            || ! in_array($command['type'] ?? null, ['security.scan.quick', 'security.scan.full', 'security.baseline.rebuild', 'security.rules.refresh', 'security.file.quarantine'], true)
            || ! is_int($command['expires_at'] ?? null) || ! is_array($command['payload'] ?? null)) {
            throw new RuntimeException('Invalid security command.');
        }
        $payload = $command['payload'];
        if ($command['type'] === 'security.file.quarantine') {
            if (count($payload) !== 2 || ! is_string($payload['file_id'] ?? null) || ! is_string($payload['sha256'] ?? null)
                || ! preg_match('/^[a-f0-9]{64}$/D', $payload['file_id']) || ! preg_match('/^[a-f0-9]{64}$/D', $payload['sha256'])) {
                throw new RuntimeException('Invalid quarantine metadata.');
            }
        } elseif ($payload !== []) {
            throw new RuntimeException('Security commands cannot contain arguments.');
        }
    }

    /** @param array<string, mixed> $command */
    private function performCommand(array $command, LocalState $state, CloudSecurityClient $client, LocalScanner $scanner, RuleUpdates $rules, Quarantine $quarantine, string $instance): string
    {
        if ($command['type'] === 'security.file.quarantine') {
            if (! config('cloud-security.scanner.quarantine_enabled', false)) {
                return 'rejected';
            }
            $quarantine->move(base_path(), $state, $command['id'], $command['payload']['file_id'], $command['payload']['sha256']);

            return 'succeeded';
        }
        $keys = (array) config('cloud-security.scanner.rule_public_keys', []);
        $minimum = (int) config('cloud-security.scanner.minimum_rule_version', 0);
        if ($command['type'] === 'security.rules.refresh') {
            $rules->install($state, $client->rules(), $keys, $minimum);

            return 'succeeded';
        }
        $pack = $rules->cached($state, $keys, $minimum);
        $report = $scanner->scan(base_path(), $state, $instance, $command['type'] !== 'security.scan.quick', (array) config('cloud-security.scanner', []), $pack);

        return $report['status'] === 'completed' ? 'succeeded' : 'incomplete';
    }
}
