# basicxii/cloud-security

Laravel client for the BasicXII Lens machine authentication protocol. Supports configuration discovery, a facade, typed successful results, redacted exceptions and the `lens:*` commands.

## Install

After publication:

```sh
composer require basicxii/cloud-security
php artisan vendor:publish --tag=cloud-security-config
```

This source has not been published. To test it locally, add a Composer `path` repository in the **customer application**, pointing to this package directory, and require `basicxii/cloud-security:*@dev`. Do not install the client into the central service: both intentionally use the configuration namespace `cloud-security` for their respective applications.

```json
{
  "repositories": [{"type": "path", "url": "../server/packages/cloud-security-laravel"}],
  "require": {"basicxii/cloud-security": "*@dev"}
}
```

The path is an example relative to the customer application's composer.json. Run `composer update basicxii/cloud-security` after adding it. Laravel auto-discovers the service provider.

```ini
LENS_PROJECT_ID=project_xxxxx
LENS_API_KEY=your_api_key
LENS_SIGNING_SECRET=your_signing_secret
LENS_ENDPOINT=https://basicxii-lens.test
LENS_PROJECT_ID=project_xxxxx
LENS_API_KEY=your_api_key
LENS_SIGNING_SECRET=your_signing_secret
LENS_ENDPOINT=https://basicxii-lens.test
CLOUD_SECURITY_TIMEOUT=5
CLOUD_SECURITY_CONNECT_TIMEOUT=3
CLOUD_SECURITY_RETRY=0
CLOUD_SECURITY_ENABLED=true
```

The application origin defaults to `APP_URL`; override with `CLOUD_SECURITY_ORIGIN`. Supply a root HTTP/HTTPS origin, without paths, query strings, fragments, or embedded credentials. API-key IDs are extracted automatically; no fifth credential environment variable is needed.

```php
use BasicXII\CloudSecurity\Facades\Lens;

$result = Lens::verify();
if ($result->allowed()) {
    // The central service authenticated this project.
}

$name = Lens::project()->projectName;
Lens::ping();
```

All methods enforce the same policies. `allowed()` describes only successful results; failures throw exceptions and never silently authorize.

```sh
php artisan lens:connect --token=your_workspace_token
```

The command verifies the configured project connection and returns a nonzero exit code on failure. Existing `CLOUD_SECURITY_*` names remain supported as a migration fallback. `cloud-security:test` remains available as a compatibility alias.

## Exceptions and transport

Catch `BasicXII\CloudSecurity\Exceptions\CloudSecurityException` or one of its subclasses:

- `ConfigurationException`: missing/invalid configuration or disabled SDK.
- `AuthenticationException`: HTTP 401.
- `AuthorizationException`: HTTP 403.
- `RateLimitException`: HTTP 429.
- `ConnectionException`: network/TLS/timeout or service error.
- `ProtocolException`: malformed success, redirects, or unsupported response.

Messages never echo remote response bodies or credentials; underlying transport exceptions are not chained. Do not log your configuration, HTTP request objects or environment values.

HTTPS and certificate verification are mandatory by default. `CLOUD_SECURITY_ALLOW_INSECURE_LOCAL=true` permits HTTP in Laravel local/testing environments only; `CLOUD_SECURITY_VERIFY_SSL=false` also requires that opt-in. Neither flag permits insecure production/staging transport. Retries are limited to transient network/server failures, use fresh nonce/signature values, and never retry authentication or policy rejection. Total elapsed time can include all configured attempts and connection timeouts.

A Laravel application using `config:cache` must rebuild configuration after changing credentials. Store secrets in environment/deployment secret management, never in source control.

## Cloud operations agent

The optional agent connects your application's schedules, Artisan commands, queue metadata, routes, Composer versions and security review observations to the project's **Operations** screen. It requires a complete Laravel application and an API key created with **Enable operational agent access** selected. Existing authentication-only keys are not automatically elevated.

Publish the configuration and enable the agent:

```sh
php artisan vendor:publish --tag=cloud-security-config
```

```ini
LENS_AGENT_ENABLED=true
LENS_INSTANCE=portal-api
```

Approve exact Artisan argument lists in `config/cloud-security.php`. The default action list is empty. The cloud can select an approved action but cannot supply arguments, options, executable paths or shell syntax:

```php
'agent' => [
    'enabled' => env('LENS_AGENT_ENABLED', false),
    'instance' => env('LENS_INSTANCE', 'default'),
    'timeout' => 300, // Hard process timeout, maximum 3600 seconds.
    'actions' => [
        'health' => ['about', '--only=environment'],
        // Add reviewed application commands here, with their exact arguments.
    ],
],
```

Preserve the other published settings, including the optional `background_logs` mapping. Its defaults read the same `background_task_infos` columns as Lens. Missing storage yields unavailable last-run metadata. Arguments are not uploaded with command definitions; their fingerprint detects configuration changes.

```sh
php artisan config:clear
php artisan lens:agent --once
# Or publish inventory with execution disabled for this synchronization:
php artisan lens:agent --inventory-only
# Keep the agent running under Supervisor, systemd or a dedicated Docker service:
php artisan lens:agent
```

For Portal, run these inside `docker exec -it api bash`. A supervised process synchronizes every 15 seconds when idle. Alternatively, schedule `cloud-security:agent --once` with `withoutOverlapping()` every minute. Use persistent `storage/app/cloud-security-agent`, one agent process per instance, and a distinct instance name per server. Separate hosts must not share one instance identity. The local journal lock prevents overlapping agents on the same persistent filesystem.

Run requests require project manager access, expire after five minutes if unclaimed, and are delivered once. A definition changed locally is rejected. Runs execute immediately, outside the scheduler, so scheduler `when()` filters, timing and overlap locks do not apply; commands that can overlap scheduled work must implement their own shared business lock. Only pending cloud requests can be cancelled. Terminating a running command requires local process supervision.

The agent journals a run before execution and retains its result until the cloud acknowledges it. Interrupted runs report `unknown` and are never automatically re-executed. A lost claim response can also leave an unknown outcome; inspect the application before requesting a new run. Claims without completion are displayed as unknown after 65 minutes. Drain the journal before rotating credentials because pending results are bound to the original credential. Cloud run history follows the server's audit retention period.

All exchanges require request signing, and the client verifies a response signature bound to the request nonce. The cloud opens no inbound connection to the application. Raw job payloads, exception traces, command output, source code, environment files and secrets are not uploaded. Command stdout/stderr are discarded; business logs remain the command's responsibility. Queue rows are currently supported for database queues; collection notices identify unavailable storage. Source review is a bounded heuristic, not a vulnerability scan, and security checks explicitly identify manual review areas.

## Tests and compatibility

```sh
composer install
composer test
```

From the central repository, the existing dependencies can run the package tests without installing more packages:

```sh
php vendor/bin/phpunit -c packages/cloud-security-laravel/phpunit.xml
```

The package declares PHP 8.2+ and Illuminate 11/12/13; Composer enforces each Illuminate version's own PHP requirements. Tests in this workspace run on PHP 8.5 and Illuminate 13. Run the supported version matrix before publishing a release.

See the central repository's `API.md` for the exact canonical signing format and `SECURITY.md` for trust assumptions.
