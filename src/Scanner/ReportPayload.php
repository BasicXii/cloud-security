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
            && in_array($report['mode'], ['quick', 'full'], true) && $report['rules_version'] === PhpAnalyzer::VERSION);
        self::check(is_array($report['summary']) && is_array($report['findings']) && count($report['findings']) <= 200 && array_is_list($report['findings']));
        self::keys($report['summary'], ['discovered', 'inspected', 'unchanged', 'new', 'modified', 'deleted', 'skipped', 'findings', 'baseline_created']);
        foreach ($report['summary'] as $key => $value) {
            self::check($key === 'baseline_created' ? is_bool($value) : (is_int($value) && $value >= 0 && $value <= 1000000));
        }
        foreach ($report['findings'] as $finding) {
            self::check(is_array($finding));
            self::keys($finding, ['file_id', 'relative_path', 'sha256', 'rule_id', 'line', 'severity', 'risk_score']);
            foreach (['file_id', 'sha256'] as $key) {
                self::check(is_string($finding[$key]) && preg_match('/^[a-f0-9]{64}$/D', $finding[$key]) === 1);
            }
            self::check($finding['relative_path'] === null || (is_string($finding['relative_path']) && strlen($finding['relative_path']) <= 300
                && preg_match('~^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[a-zA-Z0-9_./ -]+$~D', $finding['relative_path']) === 1));
            self::check(in_array($finding['rule_id'], ['PHP-EVAL', 'PHP-PROCESS', 'PHP-ENCODED-EVAL', 'PHP-UPLOAD'], true)
                && in_array($finding['severity'], ['low', 'medium', 'high'], true)
                && is_int($finding['line']) && $finding['line'] >= 1 && $finding['line'] <= 1000000
                && is_int($finding['risk_score']) && $finding['risk_score'] >= 0 && $finding['risk_score'] <= 100);
        }
        self::check(strlen(json_encode(['report' => $report], JSON_THROW_ON_ERROR)) <= 262144);

        return $report;
    }

    /** @param array<string, mixed> $values
     * @param  list<string>  $keys
     */
    private static function keys(array $values, array $keys): void
    {
        self::check(count($values) === count($keys) && array_diff(array_keys($values), $keys) === []);
    }

    private static function check(bool $valid): void
    {
        if (! $valid) {
            throw new ProtocolException('Invalid scan metadata. No scan data was sent.');
        }
    }
}
