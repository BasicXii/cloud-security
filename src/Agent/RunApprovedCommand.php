<?php

namespace BasicXII\CloudSecurity\Agent;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Cache;
use Throwable;

class RunApprovedCommand implements ShouldQueue
{
    use Queueable;

    public int $tries = 1;

    public int $timeout;

    public bool $failOnTimeout = true;

    /** @param array<string, mixed> $receipt */
    public function __construct(public array $receipt)
    {
        $this->timeout = max(1, min(3600, (int) config('cloud-security.agent.timeout', 300))) + 15;
    }

    /**
     * Execute the job.
     */
    public function handle(Executor $executor): void
    {
        $cache = Cache::store($this->receipt['store']);
        if (! $cache->add($this->receipt['key'].':started', true, 86400)) {
            return;
        }
        if (now()->timestamp >= $this->receipt['deadline']
            || $this->receipt['project'] !== (string) config('cloud-security.project_id')) {
            $result = ['status' => 'rejected', 'exit_code' => null, 'output' => 'Worker project configuration or dispatch deadline does not match.'];
        } else {
            $result = $executor->execute($this->receipt['run']);
        }
        $cache->put($this->receipt['key'].':result', $result, 86400);
    }

    public function failed(?Throwable $exception): void
    {
        Cache::store($this->receipt['store'])->add($this->receipt['key'].':result', [
            'status' => 'unknown', 'exit_code' => null,
            'output' => 'The queue worker failed before confirming a result. Inspect worker logs before retrying.',
        ], 86400);
    }
}
