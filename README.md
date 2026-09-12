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
LENS_TIMEOUT=5
LENS_CONNECT_TIMEOUT=3
LENS_RETRY=0
LENS_ENABLED=true
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

The command verifies the configured project connection and returns a nonzero exit code on failure. `lens:test` is the standard command name.

## Exceptions and transport

Catch `BasicXII\CloudSecurity\Exceptions\CloudSecurityException` or one of its subclasses:

- `ConfigurationException`: missing/invalid configuration or disabled SDK.
- `AuthenticationException`: HTTP 401.
- `AuthorizationException`: HTTP 403.
- `RateLimitException`: HTTP 429.
- `ConnectionException`: network/TLS/timeout or service error.
- `ProtocolException`: malformed success, redirects, or unsupported response.

Messages never echo remote response bodies or credentials; underlying transport exceptions are not chained. Do not log your configuration, HTTP request objects or environment values.

HTTPS and certificate verification are mandatory by default. `LENS_ALLOW_INSECURE_LOCAL=true` permits HTTP in Laravel local/testing environments only; `LENS_VERIFY_SSL=false` also requires that opt-in. Neither flag permits insecure production/staging transport. Retries are limited to transient network/server failures, use fresh nonce/signature values, and never retry authentication or policy rejection. Total elapsed time can include all configured attempts and connection timeouts.

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

For Portal, run these inside `docker exec -it api bash`. A supervised process synchronizes every 15 seconds when idle. Alternatively, schedule `lens:agent --once` with `withoutOverlapping()` every minute. Use persistent `storage/app/cloud-security-agent`, one agent process per instance, and a distinct instance name per server. Separate hosts must not share one instance identity. The local journal lock prevents overlapping agents on the same persistent filesystem.

Run requests require project manager access, expire after five minutes if unclaimed, and are delivered once. A definition changed locally is rejected. Runs execute through the configured process or queue mode, outside the scheduler, so scheduler `when()` filters, timing and overlap locks do not apply; commands that can overlap scheduled work must implement their own shared business lock. Only pending cloud requests can be cancelled. Terminating a running command requires local process supervision.

The agent journals a run before execution and retains its result until the cloud acknowledges it. Interrupted runs report `unknown` and are never automatically re-executed. A lost claim response can also leave an unknown outcome; inspect the application before requesting a new run. Claims without completion are displayed as unknown after 65 minutes. Drain the journal before rotating credentials because pending results are bound to the original credential. Cloud run history follows the server's audit retention period.

All exchanges require request signing, and the client verifies a response signature bound to the request nonce. The cloud opens no inbound connection to the application. Raw job payloads, exception traces, command output, source code, environment files and secrets are not uploaded. Command stdout/stderr are discarded; business logs remain the command's responsibility. Queue rows are currently supported for database queues; collection notices identify unavailable storage. Source review is a bounded heuristic, not a vulnerability scan, and security checks explicitly identify manual review areas.

## Dispatch commands to worker pods

Set queue execution on the client agent to run approved Artisan commands in a different pod:

```ini
LENS_AGENT_EXECUTION=queue
LENS_AGENT_QUEUE_CONNECTION=redis
LENS_AGENT_QUEUE=lens-commands
LENS_AGENT_RESULT_STORE=redis
LENS_AGENT_WAIT_TIMEOUT=900
```

Merge the package's `agent.execution` and `agent.dispatch` configuration into any previously published config, rebuild the config cache, and restart the agent and workers. `LENS_AGENT_QUEUE_CONNECTION` names a connection in `config/queue.php`; `LENS_AGENT_RESULT_STORE` names a store in `config/cache.php`. Agent and worker pods must use the same project ID, approved action definitions, SDK version, queue backend, result cache backend and cache prefix. Result cache drivers supported here are Redis, database, Memcached and DynamoDB; process-local file/array caches and synchronous queue connections are rejected.

Run a worker on the target scheduler/background pod:

```sh
php artisan queue:work redis --queue=lens-commands --tries=1 --timeout=330
```

A pod running only `schedule:run` does not consume queued jobs. Run the queue worker as a supervised pod process or sidecar and reserve this queue for the intended worker pods. With the default 300-second command timeout, the wrapper job timeout is 315 seconds; set the queue connection's `retry_after` (or SQS visibility timeout) above the worker timeout, for example 360 seconds. Increase these together if increasing `agent.timeout`. Keep the result wait timeout long enough for queue delay plus command runtime, up to 3600 seconds.

The existing Run button dispatches the approved command, and the Runs view waits for the worker's exit code and output. The agent keeps synchronizing while jobs run; results are collected on later syncs. A continuous `lens:agent` monitors automatically. When using `lens:agent --once`, keep invoking it on schedule so later invocations collect results. Dispatch receipts are journaled before enqueueing, survive agent restarts and are never automatically redispatched. Keep the agent journal on persistent storage. A failed or ambiguous enqueue is left waiting until the deadline because the broker may already have accepted it.

Workers revalidate the action fingerprint, project ID and expiry before execution. Duplicate delivery is suppressed using a shared-cache marker, retained with results for 24 hours. Do not flush or evict these keys while work is pending; command side effects should remain idempotent. Expired work is rejected. Worker crashes or a missing result at the wait deadline produce `unknown`, not a success or an automatic retry; inspect the worker before requesting another run. A command that dispatches further jobs returns when that command exits; this does not wait for those downstream jobs. Use `LENS_AGENT_EXECUTION=process` to retain direct execution on the agent.

## Dependency audits

The agent sends Composer and npm audit reports to **Operations → Dependency audits**, including package versions, advisory links, severity, affected ranges and remediation guidance. Upgrade the client SDK and restart `php artisan lens:agent` to receive reports. Older agents remain compatible but do not send audits.

```ini
LENS_AUDIT_ENABLED=true
LENS_COMPOSER_BINARY=composer
LENS_NPM_BINARY=npm
```

Audits are enabled by default with the operational agent. The binaries must be available to the agent process; the binary settings accept a local executable path, not a shell command. Merge the `agent.audit` configuration when using an already-published configuration and rebuild Laravel's configuration cache after changing environment variables.

The client runs `composer audit --locked --format=json --no-interaction --no-ansi --no-plugins --no-scripts` and `npm audit --json --package-lock-only --ignore-scripts --include=dev --include=optional --include=peer`. No installation, repair or dependency update is executed. Audits contact the client's configured registries, which receive dependency information. Only normalized findings are sent to Lens; raw output and registry credentials are withheld.

The application root must contain `composer.lock` and/or `package-lock.json` (or `npm-shrinkwrap.json`). Composer development dependencies are included. npm audit report format v2 (npm 7+) is supported; Yarn, pnpm, nested frontend directories and npm v6 reports are not supported. Missing lockfiles, tools, registry failures and unsupported output are reported as unavailable, never as a clean audit. Local Composer ignore policy is identified when returned by Composer. Exact patched versions are shown only when the audit supplies them; otherwise follow the linked advisory.

Each command has a 45-second timeout, output is bounded to 4 MB, lockfiles to 10 MB, and reports to 100 findings per manager with a truncation notice. Successful reports are cached locally for 15 minutes and failed attempts for two minutes; lockfile changes invalidate the cache. A file-cache lock prevents concurrent scans. Reports show their timestamp so offline clients cannot appear freshly scanned. The first sync may take up to 90 seconds while both tools run. After fixing dependencies, test, deploy the updated lockfile and let the next agent sync collect a fresh report.

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
