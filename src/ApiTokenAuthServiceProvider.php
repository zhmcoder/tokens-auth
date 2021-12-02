<?php

namespace Andruby\ApiToken;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class ApiTokenAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
            $this->publishes([
                __DIR__.'/../config/tokens-auth.php' => config_path('tokens-auth.php'),
            ]);
        }
        Auth::extend('tokens-auth', function ($app, $name, array $config) {
            return new ApiTokensGuard(
                Auth::createUserProvider($config['provider']),
                $app->make('request')
            );
        });

        Auth::extend('tokens-userinfo', function ($app, $name, array $config) {
            return new UserInfoTokensGuard(
                Auth::createUserProvider($config['provider']),
                $app->make('request')
            );
        });
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/tokens-auth.php', 'tokens-auth');
    }
}
