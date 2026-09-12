<?php

namespace BasicXII\CloudSecurity\Agent;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Throwable;

class Inventory
{
    public function __construct(private ActionCatalog $catalog, private DependencyAudit $audits) {}

    /** @return array<string, mixed> */
    public function collect(): array
    {
        $limits = ['Inventory is bounded: 1000 commands, 500 schedules, 2000 routes and the latest 50 queue records.'];
        $commands = [];
        foreach (Artisan::all() as $name => $command) {
            $category = 'vendor';
            try {
                $file = (new \ReflectionClass($command))->getFileName() ?: '';
                $category = str_starts_with(realpath($file) ?: '', rtrim(app_path(), DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)
                    ? 'project' : (str_contains(str_replace('\\', '/', $file), '/vendor/laravel/') ? 'laravel' : 'vendor');
            } catch (Throwable) {
            }
            $commands[] = ['name' => substr($name, 0, 160), 'description' => mb_substr($command->getDescription(), 0, 300), 'category' => $category];
        }
        $schedules = [];
        $background = $this->backgroundLogs();
        foreach (app(Schedule::class)->events() as $event) {
            $command = 'Scheduled callback or shell task';
            if (is_string($event->command) && preg_match('/artisan[\'"]?\s+[\'"]?([a-zA-Z0-9:_-]+)/', $event->command, $matches)) {
                $command = $matches[1];
            }
            $row = $background[$command] ?? [];
            $schedules[] = ['command' => $command, 'expression' => $event->expression, 'timezone' => (string) ($event->timezone ?? config('app.timezone')),
                'last_run' => $row['started'] ?? null, 'last_finished' => $row['finished'] ?? null, 'succeeded' => $row['succeeded'] ?? null];
        }
        $routes = [];
        foreach (Route::getRoutes() as $route) {
            $routes[] = ['uri' => mb_substr($route->uri(), 0, 500), 'methods' => implode('|', $route->methods()),
                'middleware' => mb_substr(implode(', ', array_filter($route->middleware(), 'is_string')), 0, 500) ?: 'None declared'];
        }
        $checks = $this->checks();
        $jobs = $this->jobs(false, $limits);
        $failed = $this->jobs(true, $limits);
        $actions = [];
        foreach ($this->catalog->all() as $id => $action) {
            $actions[] = ['id' => $id, 'command' => $action['command'], 'fingerprint' => $action['fingerprint']];
        }

        return ['runtime' => ['php' => PHP_VERSION, 'laravel' => app()->version(),
            'environment' => (string) config('app.env'), 'queue' => (string) config('queue.default'),
            'execution' => (string) config('cloud-security.agent.execution', 'process'),
            'execution_queue' => mb_substr((string) config('cloud-security.agent.dispatch.queue', 'lens-commands'), 0, 100)],
            'commands' => array_slice($commands, 0, 1000), 'schedules' => array_slice($schedules, 0, 500),
            'routes' => array_slice($routes, 0, 2000), 'jobs' => $jobs, 'failed_jobs' => $failed,
            'checks' => $checks, 'actions' => $actions, 'limits' => $limits,
            'findings' => $this->sourceReview(), 'components' => $this->components(), 'audits' => $this->audits->collect()];
    }

    /** @return list<array{path: string, line: int, rule: string}> */
    private function sourceReview(): array
    {
        $findings = [];
        $bytes = 0;
        $files = 0;
        if (! is_dir(app_path())) {
            return [];
        }
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(app_path(), \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->isLink() || ! $file->isFile() || $file->getExtension() !== 'php' || ! $file->isReadable()) {
                continue;
            }
            if (++$files > 1000 || $bytes + $file->getSize() > 16 * 1024 * 1024 || count($findings) >= 200) {
                break;
            }
            if ($file->getSize() > 512 * 1024) {
                continue;
            }
            $bytes += $file->getSize();
            $lines = file($file->getPathname(), FILE_IGNORE_NEW_LINES);
            foreach ($lines ?: [] as $line => $source) {
                if (preg_match('/\b(?:whereRaw|orWhereRaw|selectRaw|orderByRaw|havingRaw|DB::raw|DB::statement|shell_exec|exec|system|passthru)\s*\(/', $source)) {
                    $findings[] = ['path' => mb_substr('app/'.str_replace('\\', '/', substr($file->getPathname(), strlen(app_path()) + 1)), 0, 300),
                        'line' => $line + 1, 'rule' => 'Review raw query or process call for bound parameters and trusted input.'];
                    if (count($findings) >= 200) {
                        break;
                    }
                }
            }
        }

        return $findings;
    }

    /** @return list<array{name: string, version: string}> */
    private function components(): array
    {
        $path = base_path('composer.lock');
        if (! is_file($path) || filesize($path) > 5 * 1024 * 1024) {
            return [];
        }
        $lock = json_decode(file_get_contents($path), true);
        $result = [];
        foreach (array_slice($lock['packages'] ?? [], 0, 500) as $package) {
            $result[] = ['name' => mb_substr($package['name'], 0, 160), 'version' => mb_substr($package['version'], 0, 100)];
        }

        return $result;
    }

    /** @param list<string> $limits
     * @return list<array<string, mixed>>
     */
    private function jobs(bool $failed, array &$limits): array
    {
        $connection = $failed ? config('queue.failed.database') : config('queue.connections.'.config('queue.default').'.connection');
        $table = $failed ? config('queue.failed.table', 'failed_jobs') : config('queue.connections.'.config('queue.default').'.table', 'jobs');
        if (! $failed && config('queue.connections.'.config('queue.default').'.driver') !== 'database') {
            $limits[] = 'Pending job details are available for database queues only.';

            return [];
        }
        try {
            $database = DB::connection($connection);
            if (! $database->getSchemaBuilder()->hasTable($table)) {
                $limits[] = $failed ? 'Failed job storage is unavailable.' : 'Pending job storage is unavailable.';

                return [];
            }
            $columns = $failed ? ['id', 'queue', 'failed_at'] : ['id', 'queue', 'attempts', 'created_at'];

            return $database->table($table)->select($columns)->orderByDesc('id')->limit(50)->get()->map(function ($row) use ($failed): array {
                $result = ['id' => (string) $row->id, 'queue' => mb_substr($row->queue, 0, 100)];
                if ($failed) {
                    $result['failed_at'] = (string) $row->failed_at;
                } else {
                    $result['attempts'] = (int) $row->attempts;
                    $result['created_at'] = is_numeric($row->created_at) ? gmdate('c', (int) $row->created_at) : (string) $row->created_at;
                }

                return $result;
            })->all();
        } catch (Throwable) {
            $limits[] = $failed ? 'Failed job metadata could not be collected.' : 'Pending job metadata could not be collected.';

            return [];
        }
    }

    /** @return array<string, array<string, mixed>> */
    private function backgroundLogs(): array
    {
        $settings = config('cloud-security.agent.background_logs', []);
        try {
            if (empty($settings['table']) || ! DB::getSchemaBuilder()->hasTable($settings['table'])) {
                return [];
            }
            $columns = array_intersect_key($settings, array_flip(['command', 'started', 'finished', 'succeeded']));
            $rows = DB::table($settings['table'])->select(array_values($columns))->limit(500)->get();
            $result = [];
            foreach ($rows as $row) {
                $result[$row->{$columns['command']}] = [
                    'started' => $row->{$columns['started']} === null ? null : (string) $row->{$columns['started']},
                    'finished' => $row->{$columns['finished']} === null ? null : (string) $row->{$columns['finished']},
                    'succeeded' => $row->{$columns['succeeded']} === null ? null : (bool) $row->{$columns['succeeded']},
                ];
            }

            return $result;
        } catch (Throwable) {
            return [];
        }
    }

    /** @return list<array{category: string, status: string, detail: string}> */
    private function checks(): array
    {
        $check = fn (string $category, string $status, string $detail): array => compact('category', 'status', 'detail');

        return [
            $check('Broken access control', 'review', 'Review the Routes screen for authentication and authorization coverage. Middleware names alone cannot prove access control.'),
            $check('Cryptographic failures', config('session.secure') === true ? 'pass' : 'warning', 'HTTPS-only session cookie: '.(config('session.secure') === true ? 'enabled' : 'not explicitly enabled').'. Review encryption and TLS separately.'),
            $check('Injection', 'review', 'Source review lists raw query and process call locations for manual review. Heuristics can miss vulnerabilities and flag safe code. Source code is not uploaded.'),
            $check('Insecure design', 'review', 'Review tenant boundaries, business rules, abuse cases and least privilege. This requires application-specific review.'),
            $check('Security misconfiguration', config('app.debug') ? 'warning' : 'pass', 'Debug mode is '.(config('app.debug') ? 'enabled' : 'disabled').'.'),
            $check('Vulnerable and outdated components', 'review', 'Review the Dependency audits tab for client Composer and npm findings, scan status and upgrade guidance. Also audit dependencies in your build pipeline.'),
            $check('Identification and authentication failures', config('session.http_only') ? 'pass' : 'warning', 'HttpOnly session cookie: '.(config('session.http_only') ? 'enabled' : 'disabled').'. Review MFA and login throttling separately.'),
            $check('Software and data integrity failures', is_file(base_path('composer.lock')) ? 'pass' : 'warning', 'Composer lockfile: '.(is_file(base_path('composer.lock')) ? 'present' : 'missing').'. Review CI and artifact provenance separately.'),
            $check('Security logging and monitoring failures', 'review', 'Inspect failed jobs and cloud audit events. Verify alert delivery and retention in your environment.'),
            $check('Server-side request forgery', 'review', 'Review outbound URL validation, redirect handling and network egress controls. No automated SSRF probe is performed.'),
        ];
    }
}
