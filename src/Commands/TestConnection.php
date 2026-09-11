<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Exceptions\CloudSecurityException;
use Illuminate\Console\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;

class TestConnection extends Command
{
    protected $signature = 'cloud-security:test|lens:test';

    protected $description = 'Verify the Cloud Security connection, credentials, and security policies';

    public function handle(CloudSecurityClient $client): int
    {
        $this->info('Cloud Security');
        try {
            $result = $client->verify();
        } catch (CloudSecurityException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }
        $name = OutputFormatter::escape(preg_replace('/[\x00-\x1f\x7f]/', '', $result->projectName));
        $this->line('Server connection ........ OK');
        $this->line('Project .................. '.$name);
        foreach (['authentication' => 'Authentication', 'source_ip' => 'Source IP', 'domain' => 'Domain', 'signing' => 'Request signing'] as $check => $label) {
            $this->line(str_pad($label.' ', 27, '.').' '.ucfirst(str_replace('_', ' ', $result->checks[$check])));
        }
        $this->info('Integration successful.');

        return self::SUCCESS;
    }
}
