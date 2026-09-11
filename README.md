# basicxii/cloud-security

Laravel client for the Cloud Security machine authentication protocol. Supports configuration discovery, a facade, typed successful results, redacted exceptions and `cloud-security:test`.

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
CLOUD_SECURITY_URL=https://security.example.com
CLOUD_SECURITY_PROJECT_ID=prj_YOUR_PROJECT_ID
CLOUD_SECURITY_API_KEY=cs_live_YOUR_CREDENTIAL
CLOUD_SECURITY_SIGNING_SECRET=css_YOUR_SIGNING_SECRET
CLOUD_SECURITY_TIMEOUT=5
CLOUD_SECURITY_CONNECT_TIMEOUT=3
CLOUD_SECURITY_RETRY=0
CLOUD_SECURITY_ENABLED=true
```

The application origin defaults to `APP_URL`; override with `CLOUD_SECURITY_ORIGIN`. Supply a root HTTP/HTTPS origin, without paths, query strings, fragments, or embedded credentials. API-key IDs are extracted automatically; no fifth credential environment variable is needed.

```php
use BasicXII\CloudSecurity\Facades\CloudSecurity;

$result = CloudSecurity::verify();
if ($result->allowed()) {
    // The central service authenticated this project.
}

$name = CloudSecurity::project()->projectName;
CloudSecurity::ping();
```

All methods enforce the same policies. `allowed()` describes only successful results; failures throw exceptions and never silently authorize.

```sh
php artisan cloud-security:test
```

The command validates configuration, verifies the connection, prints the project name and authentication/IP/domain/signing checks, and returns a nonzero exit code on failure. Policies disabled on the server print `Not enforced`.

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
