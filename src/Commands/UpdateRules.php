<?php

namespace BasicXII\CloudSecurity\Commands;

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\Scanner\LocalState;
use BasicXII\CloudSecurity\Scanner\RuleUpdates;
use Illuminate\Console\Command;
use Throwable;

class UpdateRules extends Command
{
    protected $signature = 'lens:rules:update';

    protected $description = 'Download and verify a signed, declarative security rule pack';

    public function handle(CloudSecurityClient $client, RuleUpdates $rules): int
    {
        try {
            $keys = (array) config('cloud-security.scanner.rule_public_keys', []);
            if ($keys === []) {
                $this->error('Pin a trusted rule signing public key in the local scanner configuration first.');

                return self::FAILURE;
            }
            $state = new LocalState(storage_path('basicxii-lens/'.hash('sha256', config('cloud-security.project_id').'|'.config('cloud-security.agent.instance', 'default'))));
            $pack = $rules->install($state, $client->rules(), $keys, (int) config('cloud-security.scanner.minimum_rule_version', 0));
            $this->info('Verified security rules installed: '.$pack->name());

            return self::SUCCESS;
        } catch (Throwable) {
            $this->error('Security rule update failed. The previous cached pack was preserved. Check connectivity, pinned keys, version and expiry.');

            return self::FAILURE;
        }
    }
}
