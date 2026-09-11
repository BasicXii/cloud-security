<?php

return [
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
