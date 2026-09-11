<?php

namespace BasicXII\CloudSecurity\Agent;

use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;
use Throwable;

class Executor
{
    public function __construct(private ActionCatalog $catalog) {}

    /** @param array<string, mixed> $run
     * @return array{status: string, exit_code: int|null}
     */
    public function execute(array $run): array
    {
        $action = $this->catalog->all()[$run['action'] ?? ''] ?? null;
        if (! $action || ! is_string($run['fingerprint'] ?? null) || ! hash_equals($action['fingerprint'], $run['fingerprint'])
            || ! is_int($run['expires_at'] ?? null) || $run['expires_at'] <= time()) {
            return ['status' => 'rejected', 'exit_code' => null];
        }
        try {
            $timeout = max(1, min(3600, (int) config('cloud-security.agent.timeout', 300)));
            $process = new Process([PHP_BINARY, base_path('artisan'), ...$action['argv'], '--no-interaction', '--no-ansi'], base_path(), null, null, $timeout);
            $process->disableOutput();
            $exit = $process->run();

            return ['status' => $exit === 0 ? 'succeeded' : 'failed', 'exit_code' => $exit];
        } catch (ProcessTimedOutException) {
            return ['status' => 'timed_out', 'exit_code' => null];
        } catch (Throwable) {
            return ['status' => 'failed', 'exit_code' => null];
        }
    }
}
