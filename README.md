# Multiple Tokens Auth

> A Laravel guard for multiple token auth

## TODO
* README
* Expire tokens

php artisan vendor:publish --provider="Andruby\ApiToken\ApiTokenAuthServiceProvider"

confi/auth.php中guards下增加以下配置：
       'api' => [
            'driver' => 'tokens-auth',
            'provider' => 'api_users',
        ],
        'user' => [
            'driver' => 'tokens-userinfo',
            'provider' => 'api_users',
        ],
providers增加以下配置：
        'api_users' => [
            'driver' => 'eloquent',
            'model' => Andruby\ApiToken\ApiToken::class
        ],
数据库
php artisan migrate --path=/database/migrations/2019_06_14_000000_create_api_tokens_table.php
       