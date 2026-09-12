<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Scanner\LocalScanner;
use BasicXII\CloudSecurity\Scanner\LocalState;
use BasicXII\CloudSecurity\Scanner\RuleUpdates;
use Illuminate\Console\Command;
use Throwable;

class Scan extends Command
{
    protected $signature = 'lens:scan {--quick : Analyze changed files after hashing all eligible files} {--full : Analyze every eligible file} {--local : Save locally without synchronization} {--sync : Synchronize pending reports only}';

    protected $description = 'Scan PHP locally and synchronize security metadata only';

    public function handle(LocalScanner $scanner, CloudSecurityClient $client, RuleUpdates $rules): int
    {
        if (($this->option('quick') && $this->option('full')) || ($this->option('local') && $this->option('sync'))) {
            $this->error('Choose compatible scan options.');

            return self::INVALID;
        }
        try {
            $state = new LocalState(storage_path('basicxii-lens/'.hash('sha256', config('cloud-security.project_id').'|'.config('cloud-security.agent.instance', 'default'))));
            $report = null;
            if (! $this->option('sync')) {
                $pack = $rules->cached($state, (array) config('cloud-security.scanner.rule_public_keys', []), (int) config('cloud-security.scanner.minimum_rule_version', 0));
                $report = $scanner->scan(base_path(), $state, (string) config('cloud-security.agent.instance', 'default'),
                    (bool) $this->option('full'), (array) config('cloud-security.scanner', []), $pack);
                if ($report['summary']['rules_status'] === 'stale') {
                    $this->warn('Using expired, previously verified rules. Refresh when connectivity is available.');
                }
                $this->info('Local scan '.$report['status'].'. Source files uploaded: 0.');
                $this->line('Files analyzed: '.$report['summary']['inspected'].'; skipped: '.$report['summary']['skipped'].'; findings observed: '.$report['summary']['findings']);
            }
            if (! $this->option('local')) {
                foreach ($state->pending() as $name) {
                    $pending = $state->read($name);
                    if ($pending === null || ($client->scan($pending)['accepted'] ?? false) !== true) {
                        throw new \RuntimeException('Scan acknowledgement missing.');
                    }
                    $state->acknowledge($name);
                }
                $this->info('Pending scan metadata synchronized.');
            }

            return ($report['status'] ?? 'completed') === 'completed' ? self::SUCCESS : self::FAILURE;
        } catch (Throwable) {
            $this->error('Scan or synchronization failed. Existing local reports were retained. Check local state, configuration and connectivity; retry with lens:scan --sync.');

            return self::FAILURE;
        }
    }
}
