<?php

namespace BasicXII\CloudSecurity\Agent;

use BasicXII\CloudSecurity\Exceptions\ConfigurationException;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Throwable;

class QueuedExecution
{
    /** @param array<string, mixed> $run
     * @return array<string, mixed>
     */
    public function prepare(array $run, Executor $executor): array
    {
        $connection = (string) config('cloud-security.agent.dispatch.connection', 'redis');
        $store = (string) config('cloud-security.agent.dispatch.result_store', 'redis');
        $queue = (string) config('cloud-security.agent.dispatch.queue', 'lens-commands');
        if ($executor->approved($run) === null || ! is_string($run['id'] ?? null)
            || ! preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/Di', $run['id'])
            || ! in_array(config('queue.connections.'.$connection.'.driver'), ['redis', 'database', 'sqs', 'beanstalkd'], true)
            || ! in_array(config('cache.stores.'.$store.'.driver'), ['redis', 'database', 'memcached', 'dynamodb'], true)
            || $queue === '' || strlen($queue) > 200) {
            throw new ConfigurationException('Queue execution requires an approved action, an asynchronous queue and a shared result cache.');
        }

        return ['run' => $run, 'project' => (string) config('cloud-security.project_id'),
            'key' => 'lens:run:'.hash('sha256', config('cloud-security.project_id').'|'.$run['id']),
            'connection' => $connection, 'queue' => $queue, 'store' => $store,
            'deadline' => now()->timestamp + max(30, min(3600, (int) config('cloud-security.agent.dispatch.wait_timeout', 900)))];
    }

    /** @param array<string, mixed> $receipt */
    public function dispatch(array $receipt): void
    {
        Bus::dispatch((new RunApprovedCommand($receipt))->onConnection($receipt['connection'])->onQueue($receipt['queue']));
    }

    /** @param array<string, mixed> $receipt
     * @return array{status: string, exit_code: int|null, output: string}|null
     */
    public function result(array $receipt): ?array
    {
        try {
            $result = Cache::store($receipt['store'])->get($receipt['key'].':result');
        } catch (Throwable) {
            $result = null;
        }
        if (is_array($result)) {
            return $result;
        }
        if (now()->timestamp >= $receipt['deadline']) {
            return ['status' => 'unknown', 'exit_code' => null,
                'output' => 'No worker result arrived before the wait deadline. Check the queue worker and shared cache before requesting another run; execution may have started.'];
        }

        return null;
    }
}
