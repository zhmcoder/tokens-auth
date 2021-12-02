<?php

namespace Andruby\ApiToken;

use Illuminate\Auth\TokenGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class ApiTokensGuard extends TokenGuard
{

    public function __construct(UserProvider $provider, Request $request)
    {
        parent::__construct($provider, $request, 'token', 'api_token');
    }

    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->getTokenForRequest();

        if (!empty($token)) {
            $tokenModel = $this->provider->retrieveByCredentials([
                $this->storageKey => $token,
            ]);
            if ($tokenModel) {
                $user = $tokenModel->user;
            }
        }

        return $this->user = $user;
    }
}
