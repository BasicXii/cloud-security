<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Exceptions\CloudSecurityException;
use Illuminate\Console\Command;

class Connect extends Command
{
    protected $signature = 'lens:connect {--token= : Workspace token used to provision this project}';

    protected $description = 'Verify the configured Lens project connection';

    public function handle(CloudSecurityClient $client): int
    {
        $token = (string) $this->option('token');
        if ($token !== '') {
            $this->warn('The workspace token was accepted for this setup command. Store it as LENS_WORKSPACE_TOKEN for provisioning integrations.');
        }

        try {
            $result = $client->verify();
        } catch (CloudSecurityException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        $this->info('Lens connected successfully to '.$result->projectName.'.');

        return self::SUCCESS;
    }
}
