<?php

namespace App\Providers;

use App\Socialite\EduIDProvider;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\URL;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
        Socialite::extend('eduid', function ($app) {
            $config = $app['config']['services.eduid'];
            return new EduIDProvider(
                $app['request'],
                $config['client_id'],
                $config['client_secret'],
                \URL::to($config['redirect'])
            );
        });
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }

}
