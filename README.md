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

## Local malware scanning — Phase 1

The scanner runs in the customer application. It uses PHP tokenization and SHA-256; it does not include, require, evaluate, decompress, or execute the files it inspects. No native scanner, subprocess, queue worker, or extra Composer dependency is required by this scanner.

The Composer name remains `basicxii/cloud-security`; this change does not publish or rename it to `basicxii/lens`. Install this package in the customer application using the existing installation instructions above. Existing Lens project credentials and an API key with the `agent` ability are required to synchronize. The first valid scan registers an agent using the configured `LENS_INSTANCE`. Registration does not publish the operational inventory or claim remote commands.

```sh
php artisan lens:scan
php artisan lens:scan --quick
php artisan lens:scan --full
php artisan lens:scan --local
php artisan lens:scan --sync
```

- Default and quick scans hash every eligible file and analyze new or modified files. They do not trust size and modification time as proof that content is unchanged.
- Full scans analyze all eligible files again, including unchanged files. A bundled analyzer version change also invalidates the analysis cache.
- `--local` stores the metadata report without network access. `--sync` retries pending reports without inspecting files again.
- A scan that exceeds limits or encounters unreadable, unstable, binary, or symbolic-link entries reports `incomplete`. Its previous baseline remains intact. A nonzero exit status indicates incomplete coverage or scan/synchronization failure; a successful exit does not mean that no findings were detected.

Configuration is under `cloud-security.scanner` in the published customer configuration:

```php
'scanner' => [
    'max_files' => 20000,
    'max_file_bytes' => 524288,
    'timeout' => 120,
    'disclose_paths' => true,
],
```

Limits have hard ceilings: 50,000 eligible files, 2 MiB per file, a 3,600-second cooperative deadline, 64 nested directory separators, 200 transmitted findings per report, and 100 pending reports. The file-size ceiling is a bound on input, not total tokenizer memory. The deadline is checked between traversal and file operations; PHP cannot interrupt a blocked filesystem read portably. Lower limits for memory-constrained hosts. Reports with more than 200 findings are explicitly incomplete and preserve the earlier baseline; the first 200 findings and total observed count are retained. Complete lossless multi-batch finding delivery remains future work.

Phase 1 discovers `.php`, `.php0`–`.php9`, `.phtml`, `.phar`, and `.inc` files throughout the project, including vendor files and PHP files in storage. It excludes directories named `.git`, `node_modules`, and `basicxii-lens`, and ignores `.env`, `.env.*`, common private-key names, `.pem`, `.key`, `.crt`, and `.cer` files before reading. Symbolic links are not followed and are reported as skipped coverage. Binary PHP candidates, including binary PHARs, are skipped; archive extraction and PHP hidden inside other extensions are not implemented. Compiled Blade views are not flagged solely because they are in `storage/framework/views`.

Local state lives in `storage/basicxii-lens/<project-and-instance-hash>/`. Back up this directory and keep it outside the web server's document root, with private filesystem permissions. Linux permissions are requested as 0700 for newly created directories and 0600 for state files; Windows deployments must enforce appropriate ACLs. Use stable persistent storage and a separate instance identifier for each independently scanned deployment. Do not share one baseline across unrelated container filesystems.

The first complete scan creates an **observation baseline**, not a trusted-clean baseline. Records contain opaque path HMACs, content hashes, sizes, and timestamps. Authenticated state envelopes, atomic file replacement, and a local process lock protect against accidental corruption and overlapping writers. Reports are committed before the baseline and retained until a signed cloud acknowledgement arrives. If a response is lost, retrying the same local report ID is idempotent; a different report with the same ID is rejected. A full spool fails explicitly rather than deleting older reports. Changing project or instance configuration selects a different local state directory.

## Cloud scan contract

`POST /api/v1/client/scans` accepts a single `report` object. It reuses the existing project token, agent ability, timestamp, nonce, HMAC signature, revocation, IP/domain policies and rate limiting. Successful responses use the existing signed agent response envelope. Scan IDs are unique per registered agent and local report ID. No caller-supplied project or database agent ID is accepted; both are derived from authenticated credentials and instance.

The report contains `instance`, `local_id`, `status`, `mode`, `rules_version`, `scanned_at`, `summary`, and `findings`. Findings contain only `file_id`, optional `relative_path`, `sha256`, `rule_id`, `line`, `severity`, and `risk_score`. The client checks this closed schema before HTTP serialization, and the server validates it again. Unknown source/evidence fields and uploads are rejected. There is no arbitrary metadata JSON field and no source-upload endpoint. Disable `disclose_paths` when filenames themselves may reveal sensitive information. Hashes are fingerprints and should still be treated as sensitive metadata.

The cloud stores bounded reports in `security_scans`, linked to `project_agents`, rather than creating duplicate project/authentication infrastructure. The project Malware scans page uses the existing project policy, pagination, and shared UI components. It shows report history, heuristic findings, coverage, initial baseline status, and measured request-body bytes. Body bytes are not total network bandwidth: headers, TLS, retries, and other agent traffic add overhead. An unchanged scan sends a small summary with an empty finding list, not its baseline or file inventory.

Quick reports are deltas. An empty delta does **not** resolve earlier findings. Phase 1 stores historical observations; a persistent finding workflow, deduplicated alerts, false-positive handling, and automatic resolution are not implemented. The scanner privacy statement applies to this scan protocol. The existing optional operational agent can transmit inventory and approved-command output and must be assessed separately before making platform-wide privacy claims.

## Architecture review and next phases

The proposed local inspection / cloud correlation boundary is appropriate, with these corrections:

1. Tokenization is lexical analysis, not proof of data flow. Phase 1 identifies evaluation, process calls, decoding/evaluation co-occurrence, and PHP in public upload directories. Process calls alone are low-risk review signals, not malware verdicts. Advanced rules need scope-aware assignment/flow analysis, alias handling and tested false-positive behavior. [PHP tokenizer reference](https://www.php.net/manual/en/function.token-get-all.php).
2. The sample `$c = "e"."val"; $c($b);` does not dynamically invoke the `eval` language construct. Also, string evaluation by `assert()` was removed in PHP 8. Detection rules must respect the target PHP version. [Variable functions](https://www.php.net/manual/en/functions.variable-functions.php), [assert](https://www.php.net/manual/en/function.assert.php).
3. Compiled Blade views normally contain PHP. Their directory alone is not evidence of compromise. Use deployment context and behavioral evidence before scoring them. [Laravel Blade documentation](https://laravel.com/docs/13.x/blade).
4. A local HMAC key cannot protect against an attacker controlling both the agent and its filesystem. Neither baseline signatures nor cloud checksums prove a compromised agent is telling the truth. Future trusted baseline approval should originate from a known-good deployment and be audited; cloud-triggered baseline rebuilding must never silently accept compromise.
5. Artisan bootstraps the customer application before invoking a command. Although the scanner never executes inspected files, it cannot guarantee that compromised application bootstrap code is not run. A future standalone Composer binary that bypasses application bootstrap would provide a stronger boundary.
6. Merkle trees can compact comparisons but cannot discover changed content without trustworthy leaf updates or reading the files. Avoid claiming that a cached root eliminates disk inspection.
7. Composer installation alone cannot schedule work. An existing scheduler trigger, hosting control-panel scheduled task, or manual invocation is still required. Automatic polling and remote scan orchestration are deferred. No schedules or queue jobs are installed automatically. [Laravel scheduling](https://laravel.com/docs/13.x/scheduling).
8. Before accepting cloud rule packs, pin verification keys, sign exact bytes or a specified canonical format, enforce monotonically increasing versions and compatibility, define key rotation/revocation and stale-cache policy, and bound every rule operation. Signed declarative rules can still cause resource exhaustion. Phase 1 accepts no downloaded rules.
9. Quarantine requires explicit local authorization, path containment, a fresh expected hash, race handling, rollback, and a location that cannot be served or interpreted as PHP. Removing executable permission alone does not prevent a PHP interpreter from reading a file. Phase 1 never changes inspected files.
10. Public `.env` exposure cannot be conclusively established from local existence alone. A network check risks transmitting contents and is excluded here. Cloud request/response-body logging and third-party telemetry must also honor the metadata-only boundary.

Signed rules, genuine taint analysis, resumable multi-batch delivery, exclusions with versioned scan scope, independently trusted baselines, finding correlation, remote orchestration, quarantine, alerts, Merkle synchronization, and AI explanations remain subsequent phases. CI should exercise the package across the PHP/Laravel versions advertised by its Composer manifest and Linux/Windows before publishing; local Windows validation is not proof of every hosting platform.

Cloud deployment needs the new migration and rebuilt frontend assets. Client deployment needs the updated package; no package was published by this change.
