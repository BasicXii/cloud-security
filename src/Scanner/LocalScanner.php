<?php

namespace BasicXII\CloudSecurity\Scanner;

use FilesystemIterator;
use Generator;
use RuntimeException;
use Throwable;

class LocalScanner
{
    public function __construct(private PhpAnalyzer $analyzer) {}

    /** @param array{max_files?: int, max_file_bytes?: int, timeout?: int, disclose_paths?: bool, excluded_directories?: list<string>} $limits
     * @return array<string, mixed>
     */
    public function scan(string $root, LocalState $state, string $instance, bool $full = false, array $limits = [], ?RulePack $pack = null): array
    {
        $root = realpath($root);
        if ($root === false || ! preg_match('/^[a-zA-Z0-9_-]{1,80}$/D', $instance)) {
            throw new RuntimeException('Scanner root or instance is invalid.');
        }
        if (count($state->pending()) >= 100) {
            throw new RuntimeException('Local report queue is full. Synchronize pending reports first.');
        }
        $baseline = $state->read('baseline.json');
        $rulesVersion = $pack?->name() ?? PhpAnalyzer::VERSION;
        $previous = $baseline['files'] ?? [];
        $summary = array_fill_keys(['discovered', 'inspected', 'unchanged', 'new', 'modified', 'deleted', 'skipped', 'findings'], 0);
        $skippedFiles = [];
        $summary['baseline_created'] = $baseline === null;
        $summary['rules_status'] = $pack === null ? 'bundled' : ($pack->expiresAt <= time() ? 'stale' : 'verified');
        $files = [];
        $findings = [];
        $deadline = microtime(true) + max(1, min(3600, $limits['timeout'] ?? 120));
        $maximum = max(1, min(50000, $limits['max_files'] ?? 20000));
        $sizeLimit = max(1, min(2097152, $limits['max_file_bytes'] ?? 524288));
        $discoverySkipped = 0;
        $excludedDirectories = array_values(array_filter(array_map(fn ($value) => trim((string) $value), $limits['excluded_directories'] ?? [])));
        foreach ($this->discover($root, '', $discoverySkipped, $deadline, $excludedDirectories) as $path => $absolute) {
            if ($summary['discovered'] >= $maximum || microtime(true) >= $deadline) {
                $summary['skipped']++;
                $this->recordSkipped($skippedFiles, $path, 'scan_limit_reached', $limits);
                break;
            }
            $summary['discovered']++;
            $resolved = realpath($absolute);
            if ($resolved === false || ! str_starts_with($resolved, rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)) {
                $summary['skipped']++;
                $this->recordSkipped($skippedFiles, $path, 'unsafe_path', $limits);

                continue;
            }
            clearstatcache(true, $absolute);
            $before = @stat($absolute);
            if ($before === false || $before['size'] > $sizeLimit || is_link($absolute)) {
                $summary['skipped']++;
                $this->recordSkipped($skippedFiles, $path, $before === false ? 'unreadable_metadata' : ($before['size'] > $sizeLimit ? 'file_too_large' : 'symbolic_link'), $limits);

                continue;
            }
            $source = @file_get_contents($absolute, false, null, 0, $sizeLimit + 1);
            clearstatcache(true, $absolute);
            $after = @stat($absolute);
            $stableFields = array_flip(['dev', 'ino', 'mode', 'size', 'mtime', 'ctime']);
            if ($source === false || strlen($source) > $sizeLimit || $after === false
                || array_intersect_key($before, $stableFields) !== array_intersect_key($after, $stableFields) || str_contains($source, "\0")) {
                $summary['skipped']++;
                $this->recordSkipped($skippedFiles, $path, $source === false ? 'unreadable' : (is_string($source) && str_contains($source, "\0") ? 'binary_content' : 'file_changed_during_scan'), $limits);

                continue;
            }
            $hash = hash('sha256', $source);
            $id = $state->identifier($path);
            $files[$id] = ['sha256' => $hash, 'size' => strlen($source), 'mtime' => $after['mtime']];
            $event = ! isset($previous[$id]) ? 'new' : ($previous[$id]['sha256'] === $hash ? 'unchanged' : 'modified');
            $summary[$event]++;
            if (! $full && $event === 'unchanged' && ($baseline['rules_version'] ?? null) === $rulesVersion && ($baseline['engine'] ?? null) === RulePack::ENGINE) {
                continue;
            }
            $summary['inspected']++;
            try {
                $analysis = $this->analyzer->analyze($source, $path, $pack, $baseline !== null && $event === 'new');
            } catch (Throwable) {
                $summary['skipped']++;
                $this->recordSkipped($skippedFiles, $path, 'analysis_failed', $limits);

                continue;
            }
            foreach ($analysis as $finding) {
                $summary['findings']++;
                if (count($findings) < 200) {
                    $safePath = ($limits['disclose_paths'] ?? true) && strlen($path) <= 300
                        && preg_match('~^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[a-zA-Z0-9_./ -]+$~D', $path) ? $path : null;
                    $findings[] = ['file_id' => $id, 'relative_path' => $safePath, 'sha256' => $hash, ...$finding];
                }
            }
        }
        $summary['skipped'] += $discoverySkipped;
        $summary['skipped_files'] = $skippedFiles;
        $complete = $summary['skipped'] === 0 && $summary['findings'] <= 200;
        $summary['baseline_created'] = $baseline === null && $complete;
        if ($complete) {
            $summary['deleted'] = count(array_diff_key($previous, $files));
        }
        $uuid = sprintf('%s-%s-4%s-%s-%s', bin2hex(random_bytes(4)), bin2hex(random_bytes(2)),
            substr(bin2hex(random_bytes(2)), 1), dechex(random_int(8, 11)).substr(bin2hex(random_bytes(2)), 1), bin2hex(random_bytes(6)));
        $report = ['instance' => $instance, 'local_id' => $uuid, 'status' => $complete ? 'completed' : 'incomplete',
            'mode' => $full ? 'full' : 'quick', 'rules_version' => $rulesVersion, 'scanned_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'summary' => $summary, 'findings' => $findings];
        $state->save('report-'.$uuid.'.json', $report);
        if ($complete) {
            $state->save('baseline.json', ['engine' => RulePack::ENGINE, 'rules_version' => $rulesVersion, 'files' => $files]);
        }

        return $report;
    }

    /** @param list<array{path: ?string, reason: string}> $skippedFiles */
    private function recordSkipped(array &$skippedFiles, string $path, string $reason, array $limits): void
    {
        if (count($skippedFiles) >= 100) {
            return;
        }
        $safePath = ($limits['disclose_paths'] ?? true) && strlen($path) <= 300 ? $path : null;
        $skippedFiles[] = ['path' => $safePath, 'reason' => $reason];
    }

    /** @return Generator<string, string> */
    private function discover(string $root, string $relative, int &$skipped, float $deadline, array $excludedDirectories = []): Generator
    {
        if (substr_count($relative, '/') >= 64) {
            $skipped++;

            return;
        }
        try {
            $entries = iterator_to_array(new FilesystemIterator($root.($relative !== '' ? '/'.$relative : ''), FilesystemIterator::SKIP_DOTS), false);
            usort($entries, fn ($left, $right) => $this->priority($left) <=> $this->priority($right) ?: strcasecmp($left->getFilename(), $right->getFilename()));
            foreach ($entries as $file) {
                if (! $file instanceof \SplFileInfo) {
                    throw new RuntimeException('Unexpected filesystem entry.');
                }
                if (microtime(true) >= $deadline) {
                    $skipped++;

                    return;
                }
                $name = $file->getFilename();
                $path = $relative !== '' ? $relative.'/'.$name : $name;
                if (in_array($name, ['.git', 'node_modules', 'basicxii-lens'], true)
                    || in_array($path, $excludedDirectories, true) || in_array($name, $excludedDirectories, true)
                    || preg_match('/^(?:\.env(?:\..*)?|id_rsa|id_ed25519)$|\.(?:pem|key|crt|cer)$/i', $name)) {
                    continue;
                }
                if ($file->isLink()) {
                    $skipped++;

                    continue;
                }
                if ($file->isDir()) {
                    yield from $this->discover($root, $path, $skipped, $deadline, $excludedDirectories);
                } elseif ($file->isFile() && preg_match('/\.(?:php[0-9]?|phtml|phar|inc)$/i', $name)) {
                    yield $path => $file->getPathname();
                }
            }
        } catch (Throwable) {
            $skipped++;
        }
    }

    private function priority(\SplFileInfo $file): int
    {
        return in_array($file->getFilename(), ['app', 'routes', 'config', 'database', 'resources'], true) ? 0 : ($file->isDir() ? 1 : 2);
    }
}
