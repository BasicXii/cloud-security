<?php

namespace BasicXII\CloudSecurity\Agent;

use RuntimeException;
use Symfony\Component\Process\Process;

class AuditProcess
{
    /** @return array{exit_code: int, output: string} */
    public function run(string $manager): array
    {
        $binary = (string) config('cloud-security.agent.audit.'.$manager.'_binary', $manager);
        $arguments = $manager === 'composer'
            ? ['audit', '--locked', '--format=json', '--no-interaction', '--no-ansi', '--no-plugins', '--no-scripts']
            : ['audit', '--json', '--package-lock-only', '--ignore-scripts', '--include=dev', '--include=optional', '--include=peer'];
        $process = new Process([$binary, ...$arguments], base_path(), ['COMPOSER_NO_DEV' => '0'], null, 45);
        $output = '';
        $bytes = 0;
        $exit = $process->run(function (string $type, string $buffer) use (&$output, &$bytes, $process): void {
            $bytes += strlen($buffer);
            if ($bytes > 4 * 1024 * 1024) {
                $process->stop(0);
                throw new RuntimeException('Audit output exceeded the limit.');
            }
            if ($type === Process::OUT) {
                $output .= $buffer;
            }
            $process->clearOutput();
            $process->clearErrorOutput();
        });

        return ['exit_code' => $exit, 'output' => $output];
    }
}
