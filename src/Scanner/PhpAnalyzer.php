<?php

namespace BasicXII\CloudSecurity\Scanner;

class PhpAnalyzer
{
    public const VERSION = 'bundled-1';

    /** @return list<array{rule_id: string, line: int, severity: string, risk_score: int}> */
    public function analyze(string $source, string $path): array
    {
        $tokens = array_values(array_filter(token_get_all($source), fn ($token) => ! is_array($token)
            || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)));
        $eval = null;
        $encoded = false;
        $process = null;
        foreach ($tokens as $index => $token) {
            if (! is_array($token)) {
                continue;
            }
            if ($token[0] === T_EVAL) {
                $eval ??= $token[2];
            }
            if (! in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true) || ($tokens[$index + 1] ?? null) !== '(') {
                continue;
            }
            $previous = $tokens[$index - 1] ?? null;
            if (is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true)) {
                continue;
            }
            $name = strtolower(ltrim($token[1], '\\'));
            if (in_array($name, ['base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'hex2bin'], true)) {
                $encoded = true;
            }
            if (in_array($name, ['system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen'], true)) {
                $process ??= $token[2];
            }
        }
        $findings = [];
        if ($eval !== null) {
            $findings[] = ['rule_id' => $encoded ? 'PHP-ENCODED-EVAL' : 'PHP-EVAL', 'line' => $eval,
                'severity' => $encoded ? 'high' : 'medium', 'risk_score' => $encoded ? 70 : 40];
        }
        if ($process !== null) {
            $findings[] = ['rule_id' => 'PHP-PROCESS', 'line' => $process, 'severity' => 'low', 'risk_score' => 20];
        }
        if (preg_match('~^public/(uploads|images|files|storage)/~i', $path)) {
            $findings[] = ['rule_id' => 'PHP-UPLOAD', 'line' => 1, 'severity' => 'medium', 'risk_score' => 40];
        }

        return $findings;
    }
}
