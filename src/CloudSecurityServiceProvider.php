<?php

namespace BasicXII\CloudSecurity;

use BasicXII\CloudSecurity\Commands\TestConnection;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\ServiceProvider;

class CloudSecurityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/cloud-security.php', 'cloud-security');
        $this->app->singleton(CloudSecurityClient::class, fn ($app) => new CloudSecurityClient(
            $app->make(Factory::class), $app->make(Repository::class), $app->environment(['local', 'testing']),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([__DIR__.'/../config/cloud-security.php' => config_path('cloud-security.php')], 'cloud-security-config');
            $this->commands([TestConnection::class]);
        }
    }
}
