<?php

namespace Andruby\ApiToken;

use Illuminate\Database\Eloquent\Model;

class ApiToken extends Model
{
    protected $fillable = [
        'user_id',
        'api_token',
        'expire_at'
    ];

    public function user()
    {
        return $this->belongsTo(config('tokens-auth.model'), 'user_id', 'id');
    }
}
