<?php

namespace BasicXII\CloudSecurity\Scanner;

class PhpAnalyzer
{
    public const VERSION = 'bundled-2';

    /** @return list<array<string, mixed>> */
    public function analyze(string $source, string $path, ?RulePack $pack = null, bool $newFile = false): array
    {
        $findings = (new TokenAnalysis($source))->analyze();
        $path = strtolower(str_replace('\\', '/', $path));
        $signals = [];
        $id = null;
        if (preg_match('~^(?:public/(uploads|images|files|storage)/|storage/app/public/)~', $path)) {
            $signals[] = 'upload_directory';
            $id = 'PHP-UPLOAD';
        } elseif (preg_match('~^storage/(logs|framework/(sessions|cache))/~', $path)) {
            $signals[] = 'unexpected_php';
            $id = 'PHP-UNEXPECTED';
        }
        if (str_starts_with(basename($path), '.')) {
            $signals[] = 'hidden_php';
            $id ??= 'PHP-UNEXPECTED';
        }
        if ($id !== null) {
            if ($newFile) {
                $signals[] = 'new_file';
            }
            $findings[] = ['rule_id' => $id, 'line' => 1, 'signals' => $signals, 'input_sources' => [],
                'encoding_layers' => [], 'sink' => null, 'confidence' => 'medium'];
        }

        return (new RiskScorer)->score($findings, $pack === null ? RiskScorer::SCORES : $pack->scores);
    }
}
