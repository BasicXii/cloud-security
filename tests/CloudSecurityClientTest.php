<?php

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Exceptions\AuthenticationException;
use BasicXII\CloudSecurity\Exceptions\AuthorizationException;
use BasicXII\CloudSecurity\Exceptions\CloudSecurityException;
use BasicXII\CloudSecurity\Exceptions\ConfigurationException;
use BasicXII\CloudSecurity\Exceptions\ConnectionException;
use BasicXII\CloudSecurity\Exceptions\ProtocolException;
use BasicXII\CloudSecurity\Exceptions\RateLimitException;
use Illuminate\Config\Repository;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class CloudSecurityClientTest extends TestCase
{
    private function configuration(array $overrides = []): Repository
    {
        return new Repository(['cloud-security' => array_replace([
            'base_url' => 'https://security.example.com', 'project_id' => 'prj_01JXYZ00000000000000000000',
            'api_key' => 'cs_live_01JXYZ00000000000000000000_'.str_repeat('a', 64),
            'signing_secret' => 'css_'.str_repeat('b', 64), 'origin' => 'https://example.com',
        ], $overrides)]);
    }

    private function success(): array
    {
        return ['data' => ['allowed' => true, 'project' => ['id' => 'prj_01JXYZ00000000000000000000', 'name' => 'Customer app'],
            'checks' => ['authentication' => 'valid', 'source_ip' => 'allowed', 'domain' => 'allowed', 'signing' => 'valid']]];
    }

    public function test_it_signs_the_exact_transmitted_request(): void
    {
        $http = new Factory;
        $http->preventStrayRequests();
        $http->fake(['https://security.example.com/api/v1/client/verify' => $http->response($this->success())]);
        $config = $this->configuration();
        $client = new CloudSecurityClient($http, $config);

        $result = $client->verify();

        self::assertTrue($result->allowed());
        $http->assertSent(function (Request $request) use ($config): bool {
            $timestamp = $request->header('X-Cloud-Timestamp')[0];
            $nonce = $request->header('X-Cloud-Nonce')[0];
            $canonical = "cloud-security-v1\nPOST\n/api/v1/client/verify\nprj_01JXYZ00000000000000000000\nkey_01JXYZ00000000000000000000\nhttps://example.com\n{$timestamp}\n{$nonce}\n".hash('sha256', '[]');
            self::assertSame(hash_hmac('sha256', $canonical, $config->get('cloud-security.signing_secret')), $request->header('X-Cloud-Signature')[0]);
            self::assertSame('[]', $request->body());
            self::assertSame(['Bearer '.$config->get('cloud-security.api_key')], $request->header('Authorization'));
            self::assertGreaterThanOrEqual(22, strlen($nonce));

            return true;
        });
    }

    public static function errorCases(): array
    {
        return [[401, AuthenticationException::class], [403, AuthorizationException::class], [429, RateLimitException::class], [500, ConnectionException::class], [302, ProtocolException::class], [200, ProtocolException::class]];
    }

    #[DataProvider('errorCases')]
    public function test_errors_are_typed_and_do_not_echo_remote_secrets(int $status, string $exception): void
    {
        $http = new Factory;
        $http->preventStrayRequests();
        $config = $this->configuration();
        $http->fake(['https://security.example.com/api/v1/client/verify' => $http->response(['message' => $config->get('cloud-security.api_key')], $status)]);

        try {
            (new CloudSecurityClient($http, $config))->verify();
            self::fail('Expected a security exception.');
        } catch (CloudSecurityException $caught) {
            self::assertInstanceOf($exception, $caught);
            self::assertStringNotContainsString($config->get('cloud-security.api_key'), (string) $caught);
            self::assertNull($caught->getPrevious());
        }
    }

    public function test_connection_errors_are_redacted(): void
    {
        $http = new Factory;
        $http->preventStrayRequests();
        $http->fake(['https://security.example.com/api/v1/client/verify' => $http->failedConnection('sensitive upstream detail')]);
        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('Unable to connect to Cloud Security.');

        (new CloudSecurityClient($http, $this->configuration()))->verify();
    }

    public static function invalidConfiguration(): array
    {
        return [['enabled', false], ['base_url', 'http://security.example.com'], ['base_url', 'https://user:secret@security.example.com'], ['base_url', 'https://security.example.com/other'], ['origin', 'https://example.com/path'], ['verify_ssl', false], ['timeout', 0], ['retry', 3], ['api_key', 'bad'], ['signing_secret', 'bad']];
    }

    #[DataProvider('invalidConfiguration')]
    public function test_unsafe_configuration_fails_closed(string $key, mixed $value): void
    {
        $http = new Factory;
        $http->preventStrayRequests();
        $this->expectException(ConfigurationException::class);

        (new CloudSecurityClient($http, $this->configuration([$key => $value])))->verify();
    }

    public function test_retries_use_fresh_nonces(): void
    {
        $http = new Factory;
        $http->preventStrayRequests();
        $http->fake(['https://security.example.com/api/v1/client/verify' => $http->sequence()->pushStatus(503)->push($this->success())]);

        (new CloudSecurityClient($http, $this->configuration(['retry' => 1])))->verify();

        $requests = $http->recorded()->map(fn ($pair) => $pair[0]->header('X-Cloud-Nonce')[0]);
        self::assertCount(2, $requests);
        self::assertNotSame($requests[0], $requests[1]);
    }

    public function test_ping_and_project_use_get(): void
    {
        $http = new Factory;
        $http->preventStrayRequests();
        $http->fake(['https://security.example.com/api/v1/client/ping' => $http->response($this->success()), 'https://security.example.com/api/v1/client/project' => $http->response($this->success())]);
        $client = new CloudSecurityClient($http, $this->configuration());

        self::assertTrue($client->ping()->allowed());
        self::assertSame('Customer app', $client->project()->projectName);
        $http->assertSentCount(2);
        $http->assertSent(fn (Request $request) => $request->method() === 'GET' && $request->body() === '');
    }
}
