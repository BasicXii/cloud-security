<?php

namespace BasicXII\CloudSecurity\Scanner;

class RiskScorer
{
    public const SCORES = [
        'PHP-EVAL' => 40, 'PHP-PROCESS' => 20, 'PHP-ENCODED-EVAL' => 70, 'PHP-UPLOAD' => 40,
        'PHP-INPUT-EXEC' => 90, 'PHP-INPUT-INCLUDE' => 80, 'PHP-REMOTE-INCLUDE' => 65,
        'PHP-INPUT-UNSERIALIZE' => 65, 'PHP-DYNAMIC-CALL' => 30, 'PHP-OBFUSCATION' => 35,
        'PHP-UNEXPECTED' => 35,
    ];

    public const SIGNALS = ['http_input', 'execution', 'dynamic_call', 'encoded_payload', 'nested_encoding',
        'long_encoded_string', 'excessive_escaping', 'chr_chain', 'upload_directory', 'unexpected_php',
        'hidden_php', 'remote_include', 'new_file', 'variable_variables', 'uncertain_flow'];

    public const SOURCES = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER', 'laravel_request'];

    public const SINKS = ['eval', 'system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen', 'include', 'unserialize', 'dynamic'];

    public const ENCODERS = ['base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'hex2bin'];

    /** @param list<array<string, mixed>> $findings
     * @param  array<string, int>  $scores
     * @return list<array<string, mixed>>
     */
    public function score(array $findings, array $scores = self::SCORES): array
    {
        $allSignals = array_unique(array_merge(...array_column($findings, 'signals')));
        foreach ($findings as &$finding) {
            $score = $scores[$finding['rule_id']] ?? self::SCORES[$finding['rule_id']];
            if (in_array('execution', $finding['signals'], true)) {
                foreach (['upload_directory' => 15, 'unexpected_php' => 10, 'new_file' => 5, 'nested_encoding' => 10] as $signal => $weight) {
                    if (in_array($signal, $allSignals, true)) {
                        $score += $weight;
                        $finding['signals'][] = $signal;
                    }
                }
            }
            $finding['signals'] = array_values(array_unique($finding['signals']));
            $finding['risk_score'] = min(100, $score);
            $finding['severity'] = match (true) {
                $score >= 90 => 'critical', $score >= 65 => 'high', $score >= 35 => 'medium', $score > 0 => 'low', default => 'info',
            };
        }

        return $findings;
    }
}
