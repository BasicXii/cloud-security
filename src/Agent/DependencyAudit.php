<?php

namespace BasicXII\CloudSecurity\Agent;

use Illuminate\Support\Facades\Cache;
use RuntimeException;
use Throwable;

class DependencyAudit
{
    public function __construct(private AuditProcess $process) {}

    /** @return list<array<string, mixed>> */
    public function collect(): array
    {
        return [$this->audit('composer'), $this->audit('npm')];
    }

    /** @return array<string, mixed> */
    private function audit(string $manager): array
    {
        $report = ['manager' => $manager, 'status' => 'unavailable', 'checked_at' => now()->toIso8601String(),
            'detail' => '', 'total' => 0, 'truncated' => false, 'issues' => []];
        if (! config('cloud-security.agent.audit.enabled', true)) {
            return array_replace($report, ['status' => 'disabled', 'detail' => 'Enable LENS_AUDIT_ENABLED on the client and restart the agent.']);
        }
        $filename = $manager === 'composer' ? 'composer.lock' : (is_file(base_path('npm-shrinkwrap.json')) ? 'npm-shrinkwrap.json' : 'package-lock.json');
        $path = base_path($filename);
        if (! is_file($path)) {
            return array_replace($report, ['status' => 'missing_lockfile', 'detail' => $manager === 'composer'
                ? 'No composer.lock at the client application root. Commit and deploy the lockfile.'
                : 'No npm lockfile at the client application root. Yarn, pnpm and nested frontend projects are not scanned.']);
        }
        try {
            if (! is_readable($path) || filesize($path) > 10 * 1024 * 1024) {
                throw new RuntimeException('Unreadable or oversized lockfile.');
            }
            $contents = file_get_contents($path);
            $lockfile = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
            if (! is_array($lockfile)) {
                throw new RuntimeException('Invalid lockfile.');
            }
            $key = 'lens:audit:v1:'.hash('sha256', base_path().'|'.$manager.'|'.$contents.'|'.config('cloud-security.agent.audit.'.$manager.'_binary', $manager));
            $cache = Cache::store(config('cloud-security.agent.audit.cache_store', 'file'));
            if ($cached = $cache->get($key)) {
                return $cached;
            }
            $result = $cache->lock($key.':lock', 60)->get(function () use ($cache, $key, $manager, $report, $lockfile, $path, $contents): array {
                if ($cached = $cache->get($key)) {
                    return $cached;
                }
                try {
                    $run = $this->process->run($manager);
                    $data = json_decode($run['output'], true, 512, JSON_THROW_ON_ERROR);
                    if (! is_array($data) || isset($data['error'])) {
                        throw new RuntimeException('Audit failed.');
                    }
                    $issues = $manager === 'composer' ? $this->composerIssues($data, $lockfile) : $this->npmIssues($data, $lockfile);
                    if (hash_file('sha256', $path) !== hash('sha256', $contents)) {
                        throw new RuntimeException('Lockfile changed during the audit.');
                    }
                    if ($run['exit_code'] < 0 || $run['exit_code'] > 3 || ($run['exit_code'] !== 0 && $issues === [])) {
                        throw new RuntimeException('Audit incomplete.');
                    }
                    $priority = array_flip(['critical', 'high', 'moderate', 'low', 'info', 'unknown']);
                    usort($issues, fn (array $left, array $right): int => $priority[$left['severity']] <=> $priority[$right['severity']]);
                    $report = array_replace($report, ['status' => 'completed', 'detail' => 'Lockfile audit, including development dependencies. Results reflect registry data and local audit policy at scan time.',
                        'total' => count($issues), 'truncated' => count($issues) > 100, 'issues' => array_slice($issues, 0, 100)]);
                } catch (Throwable) {
                    $command = $manager === 'composer' ? 'composer audit --locked --format=json' : 'npm audit --json';
                    $report['detail'] = 'Audit could not complete. Run '.$command.' on the client. Check CLI availability, registry access and lockfile validity. Output is withheld to protect credentials.';
                }
                $cache->put($key, $report, $report['status'] === 'completed' ? 900 : 120);

                return $report;
            });

            return $result ?: array_replace($report, ['detail' => 'An audit is already running. Results will arrive on a later agent sync.']);
        } catch (Throwable) {
            return array_replace($report, ['detail' => 'Cannot read the lockfile or audit cache. Check client file permissions, cache configuration and the 10 MB lockfile limit.']);
        }
    }

    /** @return list<array<string, mixed>> */
    private function composerIssues(array $data, array $lockfile): array
    {
        if (! isset($data['advisories']) || ! is_array($data['advisories'])) {
            throw new RuntimeException('Unsupported Composer audit format.');
        }
        $versions = [];
        foreach (array_merge($lockfile['packages'] ?? [], $lockfile['packages-dev'] ?? []) as $package) {
            $versions[$package['name']] = $package['version'] ?? 'Unknown';
        }
        $issues = [];
        foreach (['advisories', 'ignored-advisories'] as $group) {
            foreach ($data[$group] ?? [] as $name => $advisories) {
                foreach ($advisories as $advisory) {
                    $issues[] = $this->issue($name, $versions[$name] ?? 'Unknown', $advisory['title'] ?? 'Security advisory',
                        $advisory['severity'] ?? 'unknown', $advisory['affectedVersions'] ?? 'See advisory',
                        $advisory['cve'] ?? $advisory['advisoryId'] ?? '', $advisory['link'] ?? '',
                        'Upgrade to a release outside the affected range. Review the advisory for patched versions, adjust composer.json constraints if needed, update the package with dependencies, test and redeploy.',
                        $group === 'ignored-advisories' ? 'ignored' : 'vulnerability');
                }
            }
        }
        foreach ($data['abandoned'] ?? [] as $name => $replacement) {
            $issues[] = $this->issue($name, $versions[$name] ?? 'Unknown', 'Abandoned package', 'unknown', 'All versions', '', '',
                is_string($replacement) && $replacement !== '' ? 'Evaluate migration to '.$replacement.'. Review compatibility and test before replacing the package.' : 'Find a maintained replacement, assess exposure and plan a migration.', 'abandoned');
        }

        return $issues;
    }

    /** @return list<array<string, mixed>> */
    private function npmIssues(array $data, array $lockfile): array
    {
        if (($data['auditReportVersion'] ?? null) !== 2 || ! isset($data['vulnerabilities']) || ! is_array($data['vulnerabilities'])) {
            throw new RuntimeException('Unsupported npm audit format.');
        }
        $issues = [];
        foreach ($data['vulnerabilities'] as $name => $package) {
            $versions = [];
            foreach ($package['nodes'] ?? [] as $node) {
                $version = $lockfile['packages'][$node]['version'] ?? null;
                if (is_string($version)) {
                    $versions[] = $version;
                }
            }
            $fix = $package['fixAvailable'] ?? false;
            $guidance = 'No automatic fix reported. Review the advisory, update the parent dependency or replace the package; assess mitigations until a patched release is available.';
            if ($fix === true) {
                $guidance = 'npm reports a fix. Preview with npm audit fix --dry-run, review the lockfile changes, then apply the compatible update in a development branch, test and redeploy.';
            } elseif (is_array($fix)) {
                $guidance = 'npm recommends updating '.($fix['name'] ?? $name).' to '.($fix['version'] ?? 'a patched release').'. '.(! empty($fix['isSemVerMajor']) ? 'This requires a major version change; review its migration guide. ' : '').'Update in a development branch, review the lockfile, test and redeploy.';
            }
            $advisories = array_filter($package['via'] ?? [], 'is_array');
            if ($advisories === []) {
                $advisories = [['title' => 'Affected through a vulnerable dependency: '.implode(', ', array_filter($package['via'] ?? [], 'is_string'))]];
            }
            foreach ($advisories as $advisory) {
                $issues[] = $this->issue($name, implode(', ', array_unique($versions)) ?: 'Unknown', $advisory['title'] ?? 'Security advisory',
                    $advisory['severity'] ?? $package['severity'] ?? 'unknown', $advisory['range'] ?? $package['range'] ?? 'See advisory',
                    (string) ($advisory['source'] ?? ''), $advisory['url'] ?? '', $guidance, 'vulnerability');
            }
        }

        return $issues;
    }

    /** @return array<string, mixed> */
    private function issue(string $name, string $version, string $title, string $severity, string $affected, string $id, string $url, string $fix, string $kind): array
    {
        return ['package' => mb_substr($name, 0, 160), 'version' => mb_substr($version, 0, 200), 'title' => mb_substr($title, 0, 500),
            'severity' => in_array($severity, ['critical', 'high', 'moderate', 'medium', 'low', 'info'], true) ? ($severity === 'medium' ? 'moderate' : $severity) : 'unknown',
            'affected' => mb_substr($affected, 0, 500), 'advisory' => mb_substr($id, 0, 100),
            'url' => strlen($url) <= 1000 && filter_var($url, FILTER_VALIDATE_URL) && in_array(parse_url($url, PHP_URL_SCHEME), ['http', 'https'], true) && ! parse_url($url, PHP_URL_USER) ? $url : '',
            'fix' => mb_substr($fix, 0, 1000), 'kind' => $kind];
    }
}
