<?php

return [

    /*
    |--------------------------------------------------------------------------
    | The model you want to use as the user model
    |
    */

    'model' => 'App\UcenterMember',

    /*
    |--------------------------------------------------------------------------
    | The amount of active tokens a user can have.
    | The amount of active tokens is unlimited when the value is null
    |
    */

    'total_active_tokens' => null,

    'multi_login' => false,

    'token_expire_time' => 3 * 30 * 24 * 60 * 60

];
