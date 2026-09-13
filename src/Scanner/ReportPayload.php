<?php

namespace BasicXII\CloudSecurity\Scanner;

use BasicXII\CloudSecurity\Exceptions\ProtocolException;

class ReportPayload
{
    /** @param array<string, mixed> $report
     * @return array<string, mixed>
     */
    public static function validate(array $report): array
    {
        self::keys($report, ['instance', 'local_id', 'status', 'mode', 'rules_version', 'scanned_at', 'summary', 'findings']);
        foreach (['instance' => '/^[a-zA-Z0-9_-]{1,80}$/D', 'local_id' => '/^[a-f0-9-]{36}$/D',
            'scanned_at' => '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/D'] as $key => $pattern) {
            self::check(is_string($report[$key]) && preg_match($pattern, $report[$key]) === 1);
        }
        self::check(in_array($report['status'], ['completed', 'incomplete'], true)
            && in_array($report['mode'], ['quick', 'full'], true) && is_string($report['rules_version'])
            && preg_match('/^(?:bundled-[12]|signed-[1-9][0-9]{0,9}-[a-f0-9]{12})$/D', $report['rules_version']) === 1);
        self::check(is_array($report['summary']) && is_array($report['findings']) && count($report['findings']) <= 200 && array_is_list($report['findings']));
        self::keys($report['summary'], ['discovered', 'inspected', 'unchanged', 'new', 'modified', 'deleted', 'skipped', 'findings', 'baseline_created'], ['rules_status', 'skipped_files', 'batch']);
        if (isset($report['summary']['batch'])) {
            $batch = $report['summary']['batch'];
            self::check(is_array($batch));
            self::keys($batch, ['id', 'index', 'count']);
            self::check(is_string($batch['id']) && preg_match('/^[a-f0-9-]{36}$/D', $batch['id']) === 1
                && is_int($batch['index']) && is_int($batch['count']) && $batch['count'] >= 2 && $batch['count'] <= 210
                && $batch['index'] >= 0 && $batch['index'] < $batch['count']);
        }
        foreach ($report['summary'] as $key => $value) {
            self::check(match ($key) {
                'baseline_created' => is_bool($value),
                'batch' => true,
                'rules_status' => in_array($value, ['bundled', 'verified', 'stale'], true),
                'skipped_files' => is_array($value) && array_is_list($value) && count($value) <= 100 && collect($value)->every(fn ($item) => is_array($item) && array_keys($item) === ['path', 'reason'] && ($item['path'] === null || is_string($item['path'])) && is_string($item['reason'])),
                default => is_int($value) && $value >= 0 && $value <= 1000000,
            });
        }
        foreach ($report['findings'] as $finding) {
            self::check(is_array($finding));
            self::keys($finding, ['file_id', 'relative_path', 'sha256', 'rule_id', 'line', 'severity', 'risk_score'], ['signals', 'input_sources', 'encoding_layers', 'sink', 'confidence']);
            foreach (['signals' => RiskScorer::SIGNALS, 'input_sources' => RiskScorer::SOURCES, 'encoding_layers' => RiskScorer::ENCODERS] as $field => $allowed) {
                if (isset($finding[$field])) {
                    self::check(is_array($finding[$field]) && array_is_list($finding[$field]) && count($finding[$field]) <= 16);
                    foreach ($finding[$field] as $value) {
                        self::check(in_array($value, $allowed, true));
                    }
                } elseif (array_key_exists($field, $finding)) {
                    self::check(false);
                }
            }
            if (array_key_exists('sink', $finding)) {
                self::check($finding['sink'] === null || in_array($finding['sink'], RiskScorer::SINKS, true));
            }
            if (array_key_exists('confidence', $finding)) {
                self::check(in_array($finding['confidence'], ['low', 'medium', 'high'], true));
            }
            foreach (['file_id', 'sha256'] as $key) {
                self::check(is_string($finding[$key]) && preg_match('/^[a-f0-9]{64}$/D', $finding[$key]) === 1);
            }
            self::check($finding['relative_path'] === null || (is_string($finding['relative_path']) && strlen($finding['relative_path']) <= 300
                && preg_match('~^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[a-zA-Z0-9_./ -]+$~D', $finding['relative_path']) === 1));
            self::check(in_array($finding['rule_id'], array_keys(RiskScorer::SCORES), true)
                && in_array($finding['severity'], ['info', 'low', 'medium', 'high', 'critical'], true)
                && is_int($finding['line']) && $finding['line'] >= 1 && $finding['line'] <= 1000000
                && is_int($finding['risk_score']) && $finding['risk_score'] >= 0 && $finding['risk_score'] <= 100);
        }
        self::check(strlen(json_encode(['report' => $report], JSON_THROW_ON_ERROR)) <= 262144);

        return $report;
    }

    /** @param array<string, mixed> $values
     * @param  list<string>  $keys
     * @param  list<string>  $optional
     */
    private static function keys(array $values, array $keys, array $optional = []): void
    {
        self::check(array_diff($keys, array_keys($values)) === [] && array_diff(array_keys($values), [...$keys, ...$optional]) === []);
    }

    private static function check(bool $valid): void
    {
        if (! $valid) {
            throw new ProtocolException('Invalid scan metadata. No scan data was sent.');
        }
    }
}
