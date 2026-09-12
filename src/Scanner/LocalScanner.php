<?php

namespace BasicXII\CloudSecurity\Scanner;

use FilesystemIterator;
use Generator;
use RuntimeException;
use Throwable;

class LocalScanner
{
    public function __construct(private PhpAnalyzer $analyzer) {}

    /** @param array{max_files?: int, max_file_bytes?: int, timeout?: int, disclose_paths?: bool} $limits
     * @return array<string, mixed>
     */
    public function scan(string $root, LocalState $state, string $instance, bool $full = false, array $limits = []): array
    {
        $root = realpath($root);
        if ($root === false || ! preg_match('/^[a-zA-Z0-9_-]{1,80}$/D', $instance)) {
            throw new RuntimeException('Scanner root or instance is invalid.');
        }
        if (count($state->pending()) >= 100) {
            throw new RuntimeException('Local report queue is full. Synchronize pending reports first.');
        }
        $baseline = $state->read('baseline.json');
        $previous = $baseline['files'] ?? [];
        $summary = array_fill_keys(['discovered', 'inspected', 'unchanged', 'new', 'modified', 'deleted', 'skipped', 'findings'], 0);
        $summary['baseline_created'] = $baseline === null;
        $files = [];
        $findings = [];
        $deadline = microtime(true) + max(1, min(3600, $limits['timeout'] ?? 120));
        $maximum = max(1, min(50000, $limits['max_files'] ?? 20000));
        $sizeLimit = max(1, min(2097152, $limits['max_file_bytes'] ?? 524288));
        foreach ($this->discover($root, '', $summary, $deadline) as $path => $absolute) {
            if ($summary['discovered'] >= $maximum || microtime(true) >= $deadline) {
                $summary['skipped']++;
                break;
            }
            $summary['discovered']++;
            $resolved = realpath($absolute);
            if ($resolved === false || ! str_starts_with($resolved, rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)) {
                $summary['skipped']++;

                continue;
            }
            clearstatcache(true, $absolute);
            $before = @stat($absolute);
            if ($before === false || $before['size'] > $sizeLimit || is_link($absolute)) {
                $summary['skipped']++;

                continue;
            }
            $source = @file_get_contents($absolute, false, null, 0, $sizeLimit + 1);
            clearstatcache(true, $absolute);
            $after = @stat($absolute);
            if ($source === false || strlen($source) > $sizeLimit || $before !== $after || str_contains($source, "\0")) {
                $summary['skipped']++;

                continue;
            }
            $hash = hash('sha256', $source);
            $id = $state->identifier($path);
            $files[$id] = ['sha256' => $hash, 'size' => strlen($source), 'mtime' => $after['mtime']];
            $event = ! isset($previous[$id]) ? 'new' : ($previous[$id]['sha256'] === $hash ? 'unchanged' : 'modified');
            $summary[$event]++;
            if (! $full && $event === 'unchanged' && ($baseline['rules_version'] ?? null) === PhpAnalyzer::VERSION) {
                continue;
            }
            $summary['inspected']++;
            foreach ($this->analyzer->analyze($source, $path) as $finding) {
                $summary['findings']++;
                if (count($findings) < 200) {
                    $safePath = ($limits['disclose_paths'] ?? true) && strlen($path) <= 300
                        && preg_match('~^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[a-zA-Z0-9_./ -]+$~D', $path) ? $path : null;
                    $findings[] = ['file_id' => $id, 'relative_path' => $safePath, 'sha256' => $hash, ...$finding];
                }
            }
        }
        $complete = $summary['skipped'] === 0 && $summary['findings'] <= 200;
        $summary['baseline_created'] = $baseline === null && $complete;
        if ($complete) {
            $summary['deleted'] = count(array_diff_key($previous, $files));
        }
        $uuid = sprintf('%s-%s-4%s-%s-%s', bin2hex(random_bytes(4)), bin2hex(random_bytes(2)),
            substr(bin2hex(random_bytes(2)), 1), dechex(random_int(8, 11)).substr(bin2hex(random_bytes(2)), 1), bin2hex(random_bytes(6)));
        $report = ['instance' => $instance, 'local_id' => $uuid, 'status' => $complete ? 'completed' : 'incomplete',
            'mode' => $full ? 'full' : 'quick', 'rules_version' => PhpAnalyzer::VERSION, 'scanned_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'summary' => $summary, 'findings' => $findings];
        $state->save('report-'.$uuid.'.json', $report);
        if ($complete) {
            $state->save('baseline.json', ['rules_version' => PhpAnalyzer::VERSION, 'files' => $files]);
        }

        return $report;
    }

    /** @param array<string, int|bool> $summary
     * @return Generator<string, string>
     */
    private function discover(string $root, string $relative, array &$summary, float $deadline): Generator
    {
        if (substr_count($relative, '/') >= 64) {
            $summary['skipped']++;

            return;
        }
        try {
            $iterator = new FilesystemIterator($root.($relative !== '' ? '/'.$relative : ''), FilesystemIterator::SKIP_DOTS);
            foreach ($iterator as $file) {
                if (microtime(true) >= $deadline) {
                    $summary['skipped']++;

                    return;
                }
                $name = $file->getFilename();
                $path = $relative !== '' ? $relative.'/'.$name : $name;
                if (in_array($name, ['.git', 'node_modules', 'basicxii-lens'], true)
                    || preg_match('/^(?:\.env(?:\..*)?|id_rsa|id_ed25519)$|\.(?:pem|key|crt|cer)$/i', $name)) {
                    continue;
                }
                if ($file->isLink()) {
                    $summary['skipped']++;

                    continue;
                }
                if ($file->isDir()) {
                    yield from $this->discover($root, $path, $summary, $deadline);
                } elseif ($file->isFile() && preg_match('/\.(?:php[0-9]?|phtml|phar|inc)$/i', $name)) {
                    yield $path => $file->getPathname();
                }
            }
        } catch (Throwable) {
            $summary['skipped']++;
        }
    }
}
