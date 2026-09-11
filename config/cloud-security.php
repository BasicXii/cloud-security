<?php

return [
    'agent' => [
        'enabled' => env('CLOUD_SECURITY_AGENT_ENABLED', false),
        'instance' => env('CLOUD_SECURITY_INSTANCE', 'default'),
        'timeout' => 300,
        // Exact Artisan argument vectors, approved locally. No shell expressions or remote parameters.
        // 'actions' => ['health' => ['about', '--only=environment']],
        'actions' => [],
        'background_logs' => [
            'table' => 'background_task_infos', 'command' => 'task_name',
            'started' => 'last_run', 'finished' => 'last_run_finished', 'succeeded' => 'last_job_succeeded',
        ],
    ],
    'enabled' => env('CLOUD_SECURITY_ENABLED', true),
    'base_url' => env('CLOUD_SECURITY_URL', ''),
    'project_id' => env('CLOUD_SECURITY_PROJECT_ID', ''),
    'api_key' => env('CLOUD_SECURITY_API_KEY', ''),
    'signing_secret' => env('CLOUD_SECURITY_SIGNING_SECRET', ''),
    'origin' => env('CLOUD_SECURITY_ORIGIN', env('APP_URL', '')),
    'timeout' => (int) env('CLOUD_SECURITY_TIMEOUT', 5),
    'connect_timeout' => (int) env('CLOUD_SECURITY_CONNECT_TIMEOUT', 3),
    'retry' => (int) env('CLOUD_SECURITY_RETRY', 0),
    'verify_ssl' => env('CLOUD_SECURITY_VERIFY_SSL', true),
    'allow_insecure_local' => env('CLOUD_SECURITY_ALLOW_INSECURE_LOCAL', false),
];
