<?php

return [
    'scanner' => [
        'max_files' => 20000,
        'max_file_bytes' => 524288,
        'timeout' => 120,
        'disclose_paths' => true,
    ],
    'agent' => [
        'enabled' => env('LENS_AGENT_ENABLED', false),
        'instance' => env('LENS_INSTANCE', 'default'),
        'timeout' => 300,
        'execution' => env('LENS_AGENT_EXECUTION', 'process'),
        'dispatch' => [
            'connection' => env('LENS_AGENT_QUEUE_CONNECTION', 'redis'),
            'queue' => env('LENS_AGENT_QUEUE', 'lens-commands'),
            'result_store' => env('LENS_AGENT_RESULT_STORE', 'redis'),
            'wait_timeout' => (int) env('LENS_AGENT_WAIT_TIMEOUT', 900),
        ],
        'audit' => [
            'enabled' => env('LENS_AUDIT_ENABLED', true),
            'composer_binary' => env('LENS_COMPOSER_BINARY', 'composer'),
            'npm_binary' => env('LENS_NPM_BINARY', 'npm'),
            'cache_store' => 'file',
        ],
        // Exact Artisan argument vectors, approved locally. No shell expressions or remote parameters.
        // 'actions' => ['health' => ['about', '--only=environment']],
        'actions' => [],
        'background_logs' => [
            'table' => 'background_task_infos', 'command' => 'task_name',
            'started' => 'last_run', 'finished' => 'last_run_finished', 'succeeded' => 'last_job_succeeded',
        ],
    ],
    'enabled' => env('LENS_ENABLED', true),
    'base_url' => env('LENS_ENDPOINT', ''),
    'project_id' => env('LENS_PROJECT_ID', ''),
    'api_key' => env('LENS_API_KEY', ''),
    'signing_secret' => env('LENS_SIGNING_SECRET', ''),
    'workspace_token' => env('LENS_WORKSPACE_TOKEN', ''),
    'origin' => env('LENS_ORIGIN', env('APP_URL', '')),
    'timeout' => (int) env('LENS_TIMEOUT', 5),
    'connect_timeout' => (int) env('LENS_CONNECT_TIMEOUT', 3),
    'retry' => (int) env('LENS_RETRY', 0),
    'verify_ssl' => env('LENS_VERIFY_SSL', true),
    'allow_insecure_local' => env('LENS_ALLOW_INSECURE_LOCAL', false),
];
