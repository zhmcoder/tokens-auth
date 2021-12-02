<?php

namespace Andruby\ApiToken;

use App\Models\UcenterMember;
use Illuminate\Auth\TokenGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Cache;

class UserInfoTokensGuard extends TokenGuard
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
//                Cache::remember('sdfs',3600,$user);
            }
        }
        //always return user model for check return true
        if ($user == null) {
            $user = new  UcenterMember();
        }

        return $this->user = $user;


    }

    public function id()
    {
        $user = null;
        $token = $this->getTokenForRequest();
        if (!empty($token)) {
            $user_id = Cache::get('token_user_id_' . $token);
            if ($user_id) {
                return $user_id;
            }
            $tokenModel = $this->provider->retrieveByCredentials([
                $this->storageKey => $token,
            ]);
            if ($user = $tokenModel) {
                $user = $tokenModel->user;
                Cache::put('token_user_id_' . $token, $user->id, config('tokens-auth.token_expire_time'));
                return $user->id;
            }
        }
        return null;
    }

}
