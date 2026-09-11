<?php

namespace BasicXII\CloudSecurity;

use BasicXII\CloudSecurity\DTO\VerificationResult;
use BasicXII\CloudSecurity\Exceptions\AuthenticationException;
use BasicXII\CloudSecurity\Exceptions\AuthorizationException;
use BasicXII\CloudSecurity\Exceptions\ConfigurationException;
use BasicXII\CloudSecurity\Exceptions\ConnectionException;
use BasicXII\CloudSecurity\Exceptions\ProtocolException;
use BasicXII\CloudSecurity\Exceptions\RateLimitException;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Client\ConnectionException as HttpConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Str;

class CloudSecurityClient
{
    public function __construct(private Factory $http, private Repository $config, private bool $localEnvironment = false) {}

    public function ping(): VerificationResult
    {
        return $this->send('GET', '/api/v1/client/ping');
    }

    public function verify(): VerificationResult
    {
        return $this->send('POST', '/api/v1/client/verify');
    }

    public function project(): VerificationResult
    {
        return $this->send('GET', '/api/v1/client/project');
    }

    /** @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    public function agent(string $operation, array $payload): array
    {
        if ($operation !== 'poll' && ! preg_match('/^runs\/[0-9A-HJKMNP-TV-Z]{26}$/Di', $operation)) {
            throw new ProtocolException('Invalid agent operation.');
        }

        return $this->send('POST', '/api/v1/client/agent/'.$operation, $payload);
    }

    /** @param array<string, mixed>|null $payload
     * @return VerificationResult|array<string, mixed>
     */
    private function send(string $method, string $path, ?array $payload = null): VerificationResult|array
    {
        $settings = $this->settings();
        if ($payload !== null && $settings['signing_secret'] === '') {
            throw new ConfigurationException('The agent requires a signing secret.');
        }
        $body = $payload !== null ? json_encode($payload, JSON_THROW_ON_ERROR) : ($method === 'POST' ? '[]' : '');
        $attempts = $payload !== null ? 1 : $settings['retry'] + 1;
        for ($attempt = 0; $attempt < $attempts; $attempt++) {
            $timestamp = (string) time();
            $nonce = (string) Str::uuid();
            $headers = ['X-Cloud-Project' => $settings['project_id'], 'X-Cloud-Timestamp' => $timestamp,
                'X-Cloud-Nonce' => $nonce, 'X-Cloud-Origin' => $settings['origin']];
            if ($settings['signing_secret'] !== '') {
                $canonical = implode("\n", ['cloud-security-v1', $method, $path, $settings['project_id'], $settings['key_id'],
                    $settings['origin'], $timestamp, $nonce, hash('sha256', $body)]);
                $headers['X-Cloud-Signature'] = hash_hmac('sha256', $canonical, $settings['signing_secret']);
            }
            $pending = $this->http->acceptJson()->withToken($settings['api_key'])->withUserAgent('CloudSecurityLaravel/1.0')
                ->withHeaders($headers)->timeout($settings['timeout'])->connectTimeout($settings['connect_timeout'])
                ->withOptions(['verify' => $settings['verify_ssl'], 'allow_redirects' => false]);
            try {
                $response = $pending->send($method, $settings['base_url'].$path, ['body' => $body, 'headers' => ['Content-Type' => 'application/json']]);
            } catch (HttpConnectionException) {
                if ($attempt + 1 < $attempts) {
                    usleep(100000 * ($attempt + 1));

                    continue;
                }
                throw new ConnectionException('Unable to connect to Cloud Security. Check connectivity and TLS configuration.');
            }
            if ($response->status() === 401) {
                throw new AuthenticationException('Cloud Security credentials are invalid, expired, or revoked.');
            }
            if ($response->status() === 403) {
                throw new AuthorizationException('Cloud Security rejected a security policy. Check the project request logs.');
            }
            if ($response->status() === 429) {
                throw new RateLimitException('Cloud Security rate limit exceeded. Try again later.');
            }
            if ($response->serverError()) {
                if ($attempt + 1 < $attempts) {
                    usleep(100000 * ($attempt + 1));

                    continue;
                }
                throw new ConnectionException('Cloud Security is temporarily unavailable.');
            }
            if ($response->status() !== 200) {
                throw new ProtocolException('Cloud Security returned an unexpected response.');
            }
            $data = $response->json('data');
            if ($payload !== null) {
                $canonical = implode("\n", ['cloud-security-agent-v1', $nonce, hash('sha256', $response->body())]);
                if (! is_array($data) || ! hash_equals(hash_hmac('sha256', $canonical, $settings['signing_secret']), $response->header('X-Cloud-Response-Signature'))) {
                    throw new ProtocolException('The agent response signature is invalid.');
                }

                return $data;
            }
            if (! is_array($data) || ($data['allowed'] ?? null) !== true || ! is_array($data['project'] ?? null)
                || ($data['project']['id'] ?? null) !== $settings['project_id'] || ! is_string($data['project']['name'] ?? null)
                || ! is_array($data['checks'] ?? null)) {
                throw new ProtocolException('Cloud Security returned an invalid verification result.');
            }
            $checks = $data['checks'];
            if (($checks['authentication'] ?? null) !== 'valid'
                || ! in_array($checks['source_ip'] ?? null, ['allowed', 'not_enforced'], true)
                || ! in_array($checks['domain'] ?? null, ['allowed', 'not_enforced'], true)
                || ! in_array($checks['signing'] ?? null, ['valid', 'not_enforced'], true)
                || ($settings['signing_secret'] !== '' && $checks['signing'] !== 'valid')) {
                throw new ProtocolException('Cloud Security returned invalid security checks.');
            }

            return new VerificationResult($settings['project_id'], $data['project']['name'], $checks);
        }
        throw new ConnectionException('Unable to connect to Cloud Security.');
    }

    /** @return array{base_url: string, project_id: string, api_key: string, key_id: string, signing_secret: string, origin: string, timeout: int, connect_timeout: int, retry: int, verify_ssl: bool} */
    private function settings(): array
    {
        $values = $this->config->get('cloud-security', []);
        if (($values['enabled'] ?? true) !== true) {
            throw new ConfigurationException('Cloud Security is disabled; verification is unavailable.');
        }
        foreach (['base_url', 'project_id', 'api_key', 'origin'] as $field) {
            if (! is_string($values[$field] ?? null) || $values[$field] === '' || preg_match('/[\x00-\x20\x7f]/', $values[$field])) {
                throw new ConfigurationException('Cloud Security configuration is incomplete or invalid.');
            }
        }
        $url = parse_url($values['base_url']);
        $origin = parse_url($values['origin']);
        $allowInsecure = $this->localEnvironment && ($values['allow_insecure_local'] ?? false) === true;
        if ($url === false || ! isset($url['host'], $url['scheme']) || ! in_array($url['scheme'], $allowInsecure ? ['http', 'https'] : ['https'], true)
            || isset($url['user']) || isset($url['pass']) || isset($url['query']) || isset($url['fragment'])
            || ! in_array($url['path'] ?? '', ['', '/'], true)
            || $origin === false || ! isset($origin['host'], $origin['scheme']) || ! in_array($origin['scheme'], ['http', 'https'], true)
            || isset($origin['user']) || isset($origin['pass']) || isset($origin['query']) || isset($origin['fragment']) || ! in_array($origin['path'] ?? '', ['', '/'], true)) {
            throw new ConfigurationException('Use a valid HTTPS service URL and an application origin without paths or credentials.');
        }
        if (! preg_match('/^prj_[0-9A-HJKMNP-TV-Z]{26}$/D', $values['project_id'])
            || ! preg_match('/^cs_(live|test)_([0-9A-HJKMNP-TV-Z]{26})_[a-f0-9]{64}$/D', $values['api_key'], $matches)) {
            throw new ConfigurationException('Cloud Security project or API key has an invalid format.');
        }
        $secret = $values['signing_secret'] ?? '';
        if (! is_string($secret) || ($secret !== '' && ! preg_match('/^css_[a-f0-9]{64}$/D', $secret))) {
            throw new ConfigurationException('Cloud Security signing secret has an invalid format.');
        }
        $verifySsl = $values['verify_ssl'] ?? true;
        if (! is_bool($verifySsl) || (! $verifySsl && ! $allowInsecure)) {
            throw new ConfigurationException('TLS verification is required outside explicitly enabled local development.');
        }
        foreach (['timeout' => 5, 'connect_timeout' => 3, 'retry' => 0] as $field => $default) {
            $values[$field] ??= $default;
            if (! is_int($values[$field]) || $values[$field] < ($field === 'retry' ? 0 : 1) || $values[$field] > ($field === 'retry' ? 2 : 30)) {
                throw new ConfigurationException('Cloud Security timeouts or retry limits are invalid.');
            }
        }

        return ['base_url' => rtrim($values['base_url'], '/'), 'project_id' => $values['project_id'], 'api_key' => $values['api_key'],
            'key_id' => 'key_'.$matches[2], 'signing_secret' => $secret, 'origin' => rtrim($values['origin'], '/'),
            'timeout' => $values['timeout'], 'connect_timeout' => $values['connect_timeout'], 'retry' => $values['retry'], 'verify_ssl' => $verifySsl];
    }
}
