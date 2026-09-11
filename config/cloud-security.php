<?php

return [
    'agent' => [
        'enabled' => env('LENS_AGENT_ENABLED', env('CLOUD_SECURITY_AGENT_ENABLED', false)),
        'instance' => env('LENS_INSTANCE', env('CLOUD_SECURITY_INSTANCE', 'default')),
        'timeout' => 300,
        // Exact Artisan argument vectors, approved locally. No shell expressions or remote parameters.
        // 'actions' => ['health' => ['about', '--only=environment']],
        'actions' => [],
        'background_logs' => [
            'table' => 'background_task_infos', 'command' => 'task_name',
            'started' => 'last_run', 'finished' => 'last_run_finished', 'succeeded' => 'last_job_succeeded',
        ],
    ],
    'enabled' => env('LENS_ENABLED', env('CLOUD_SECURITY_ENABLED', true)),
    'base_url' => env('LENS_ENDPOINT', env('CLOUD_SECURITY_URL', '')),
    'project_id' => env('LENS_PROJECT_ID', env('CLOUD_SECURITY_PROJECT_ID', '')),
    'api_key' => env('LENS_API_KEY', env('CLOUD_SECURITY_API_KEY', '')),
    'signing_secret' => env('LENS_SIGNING_SECRET', env('CLOUD_SECURITY_SIGNING_SECRET', '')),
    'workspace_token' => env('LENS_WORKSPACE_TOKEN', ''),
    'origin' => env('LENS_ORIGIN', env('CLOUD_SECURITY_ORIGIN', env('APP_URL', ''))),
    'timeout' => (int) env('LENS_TIMEOUT', env('CLOUD_SECURITY_TIMEOUT', 5)),
    'connect_timeout' => (int) env('LENS_CONNECT_TIMEOUT', env('CLOUD_SECURITY_CONNECT_TIMEOUT', 3)),
    'retry' => (int) env('LENS_RETRY', env('CLOUD_SECURITY_RETRY', 0)),
    'verify_ssl' => env('LENS_VERIFY_SSL', env('CLOUD_SECURITY_VERIFY_SSL', true)),
    'allow_insecure_local' => env('LENS_ALLOW_INSECURE_LOCAL', env('CLOUD_SECURITY_ALLOW_INSECURE_LOCAL', false)),
];
