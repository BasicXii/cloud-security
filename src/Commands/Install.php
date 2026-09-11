<?php

namespace BasicXII\CloudSecurity\Commands;

use Illuminate\Console\Command;

class Install extends Command
{
    protected $signature = 'lens:install';

    protected $description = 'Publish the BasicXII Lens configuration file';

    public function handle(): int
    {
        $this->call('vendor:publish', ['--tag' => 'cloud-security-config', '--force' => true]);
        $this->info('Lens installed. Add LENS_PROJECT_ID, LENS_API_KEY and LENS_ENDPOINT to your .env file.');

        return self::SUCCESS;
    }
}
