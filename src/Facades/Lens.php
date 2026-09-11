<?php

namespace BasicXII\CloudSecurity\Facades;

use BasicXII\CloudSecurity\CloudSecurityClient;
use BasicXII\CloudSecurity\DTO\VerificationResult;
use Illuminate\Support\Facades\Facade;

/**
 * @method static VerificationResult ping()
 * @method static VerificationResult verify()
 * @method static VerificationResult project()
 */
class Lens extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return CloudSecurityClient::class;
    }
}
