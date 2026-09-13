<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\Scanner\LocalState;
use BasicXII\CloudSecurity\Scanner\Quarantine;
use Illuminate\Console\Command;
use Throwable;

class RestoreQuarantine extends Command
{
    protected $signature = 'lens:quarantine:restore {id : Quarantine command identifier} {--approve : Explicitly approve returning this file to the application}';

    protected $description = 'Restore a quarantined file locally without overwriting an existing file';

    public function handle(Quarantine $quarantine): int
    {
        if (! $this->option('approve')) {
            $this->error('Review the file locally first, then pass --approve to authorize restoring it.');

            return self::INVALID;
        }
        try {
            $state = new LocalState(storage_path('basicxii-lens/'.hash('sha256', config('cloud-security.project_id').'|'.config('cloud-security.agent.instance', 'default'))));
            $quarantine->restore(base_path(), $state, (string) $this->argument('id'));
            $this->info('File restored locally. Run lens:scan --full to update cloud findings.');

            return self::SUCCESS;
        } catch (Throwable) {
            $this->error('Recovery failed. Check the identifier, signed local metadata, destination and quarantined file hash.');

            return self::FAILURE;
        }
    }
}
