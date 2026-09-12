<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\Agent\Executor;
use BasicXII\CloudSecurity\Agent\Inventory;
use BasicXII\CloudSecurity\Agent\QueuedExecution;
use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Exceptions\ConfigurationException;
use Illuminate\Console\Command;
use RuntimeException;
use Throwable;

class RunAgent extends Command
{
    protected $signature = 'lens:agent {--once : Sync and process or dispatch at most one remote action} {--inventory-only : Sync without claiming work}';

    protected $aliases = ['cloud-security:agent'];

    protected $description = 'Publish operational inventory and execute locally approved cloud actions';

    public function handle(CloudSecurityClient $client, Inventory $inventory, Executor $executor): int
    {
        if (config('cloud-security.agent.enabled') !== true) {
            $this->error('Enable LENS_AGENT_ENABLED and grant this API key the agent ability first.');

            return self::FAILURE;
        }
        $instance = config('cloud-security.agent.instance', 'default');
        if (! is_string($instance) || ! preg_match('/^[a-zA-Z0-9_-]{1,80}$/D', $instance)) {
            $this->error('LENS_INSTANCE must contain 1–80 letters, digits, underscores or hyphens.');

            return self::FAILURE;
        }
        $directory = storage_path('app/cloud-security-agent/'.hash('sha256', config('cloud-security.project_id').'|'.$instance));
        if (! is_dir($directory) && ! mkdir($directory, 0700, true) && ! is_dir($directory)) {
            $this->error('Unable to create the agent journal.');

            return self::FAILURE;
        }
        $lock = fopen($directory.'/agent.lock', 'c');
        if ($lock === false || ! flock($lock, LOCK_EX | LOCK_NB)) {
            $this->warn('An agent is already running for this instance.');

            return self::FAILURE;
        }
        try {
            do {
                try {
                    $this->flush($directory, $instance, $client);
                    $snapshot = $inventory->collect();
                    if ($this->option('inventory-only')) {
                        $snapshot['actions'] = [];
                    }
                    $response = $client->agent('poll', compact('instance', 'snapshot'));
                    $run = $response['run'] ?? null;
                    if ($run !== null) {
                        if (! is_array($run) || ! is_string($run['id'] ?? null) || ! preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/Di', $run['id'])) {
                            throw new RuntimeException('Invalid remote run.');
                        }
                        $path = $directory.'/'.$run['id'].'.json';
                        if (! is_file($path)) {
                            $this->persist($path, ['status' => 'unknown', 'exit_code' => null, 'output' => '']);
                            if ($this->option('inventory-only')) {
                                $this->persist($path, ['status' => 'rejected', 'exit_code' => null, 'output' => '']);
                            } elseif (config('cloud-security.agent.execution', 'process') === 'queue') {
                                try {
                                    $queued = app(QueuedExecution::class);
                                    $receipt = $queued->prepare($run, $executor);
                                    $this->persist($path, ['queued' => $receipt]);
                                    $queued->dispatch($receipt);
                                } catch (ConfigurationException) {
                                    $this->persist($path, ['status' => 'rejected', 'exit_code' => null,
                                        'output' => 'Check the approved action, asynchronous queue connection and shared result cache configuration.']);
                                }
                            } elseif (config('cloud-security.agent.execution', 'process') === 'process') {
                                $this->persist($path, $executor->execute($run));
                            } else {
                                $this->persist($path, ['status' => 'rejected', 'exit_code' => null, 'output' => 'Unsupported agent execution mode.']);
                            }
                        }
                        $this->flush($directory, $instance, $client);
                    }
                    $this->info('Inventory synchronized.');
                } catch (Throwable $exception) {
                    report($exception);
                    $this->error('Agent sync failed. Check credentials, agent ability, connectivity and cloud request logs.');
                    if ($this->option('once') || $this->option('inventory-only')) {
                        return self::FAILURE;
                    }
                }
                if ($this->option('once') || $this->option('inventory-only')) {
                    break;
                }
                sleep(15);
            } while (true);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }

        return self::SUCCESS;
    }

    /** @param array<string, mixed> $result */
    private function persist(string $path, array $result): void
    {
        $temporary = $path.'.tmp';
        $stream = fopen($temporary, 'wb');
        if ($stream === false) {
            throw new RuntimeException('Unable to persist run state.');
        }
        try {
            $data = json_encode($result, JSON_THROW_ON_ERROR);
            if (fwrite($stream, $data) !== strlen($data) || ! fflush($stream) || ! fsync($stream)) {
                throw new RuntimeException('Unable to persist run state.');
            }
        } finally {
            fclose($stream);
        }
        if (! rename($temporary, $path)) {
            throw new RuntimeException('Unable to persist run state.');
        }
    }

    private function flush(string $directory, string $instance, CloudSecurityClient $client): void
    {
        foreach (glob($directory.'/*.json') ?: [] as $path) {
            $result = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
            if (isset($result['queued'])) {
                $result = app(QueuedExecution::class)->result($result['queued']);
                if ($result === null) {
                    continue;
                }
                $this->persist($path, $result);
            }
            $client->agent('runs/'.basename($path, '.json'), ['instance' => $instance, ...$result]);
            unlink($path);
        }
    }
}
