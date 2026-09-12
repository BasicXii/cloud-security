<?php

namespace BasicXII\CloudSecurity\Agent;

use BasicXII\CloudSecurity\Exceptions\ConfigurationException;
use Illuminate\Support\Facades\Artisan;

class ActionCatalog
{
    /** @return array<string, array{argv: list<string>, fingerprint: string, command: string}> */
    public function all(): array
    {
        $actions = [];
        foreach (config('cloud-security.agent.actions', []) as $id => $argv) {
            if (! is_string($id) || ! preg_match('/^[a-zA-Z0-9_-]{1,80}$/D', $id)
                || ! is_array($argv) || ! array_is_list($argv) || count($argv) < 1 || count($argv) > 50
                || count(array_filter($argv, fn ($part) => is_string($part) && strlen($part) <= 1000 && ! str_contains($part, "\0"))) !== count($argv)
                || ! isset(Artisan::all()[$argv[0]])
                || str_starts_with($argv[0], 'lens:')
                || str_starts_with($argv[0], 'cloud-security:')) {
                throw new ConfigurationException(json_encode(['test' => $argv[0]]));
            }
            $actions[$id] = ['argv' => $argv, 'command' => $argv[0],
                'fingerprint' => hash('sha256', json_encode($argv, JSON_THROW_ON_ERROR))];
        }
        if (config('cloud-security.agent.discover_project_actions', false)) {
            foreach (Artisan::all() as $command => $instance) {
                if (isset($actions[$command]) || str_starts_with($command, 'lens:') || str_starts_with($command, 'cloud-security:')) {
                    continue;
                }
                try {
                    $reflection = new \ReflectionClass($instance);
                    $file = $reflection->getFileName();
                } catch (\ReflectionException) {
                    $file = false;
                }
                if (! is_string($file) || ! str_starts_with(realpath($file) ?: '', rtrim(base_path('app'), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)) {
                    continue;
                }
                $id = 'discovered-'.preg_replace('/[^a-zA-Z0-9_-]+/', '-', $command);
                $argv = [$command];
                $actions[$id] = ['argv' => $argv, 'command' => $command,
                    'fingerprint' => hash('sha256', json_encode($argv, JSON_THROW_ON_ERROR))];
            }
        }
        if (count($actions) > 100) {
            throw new ConfigurationException('At most 100 remote actions may be approved.');
        }

        return $actions;
    }
}
