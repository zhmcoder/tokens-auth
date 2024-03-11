<?php

namespace Andruby\ApiToken;

use Illuminate\Auth\TokenGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

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
        debug_log_info('request token = ' . $token);
        if (!empty($token)) {
            $tokenModel = $this->provider->retrieveByCredentials([
                $this->storageKey => $token,
                function ($query) {
                    $query->where('expire_at', '>', time());
                }
            ]);
            if ($tokenModel) {
                $user = $tokenModel->user;
            }
        }

        return $this->user = $user;
    }

    public function attempt(array $credentials = [], $remember = false)
    {
//        $this->fireAttemptEvent($credentials, $remember);


        $this->lastAttempted = $user = $this->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
//            $this->login($user, $remember);

            return $user;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
//        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials) ||
            (count($credentials) === 1 &&
                Str::contains($this->firstCredentialKey($credentials), 'password'))) {
            return;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // Eloquent User "model" that will be utilized by the Guard instances.

        $model = config('tokens-auth.model');
        $model = new $model();
        $query = $model::query();


        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    protected function hasValidCredentials($user, $credentials)
    {
        $validated = !is_null($user) && $this->provider->validateCredentials($user, $credentials);

//        if ($validated) {
//            $this->fireValidatedEvent($user);
//        }

        return $validated;
    }

    public function logout()
    {
        $user = $this->user();
        $this->clearUserData($user);
        if (!is_null($this->user) && !empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }

    protected function clearUserData(AuthenticatableContract $user)
    {
        $token = $this->getTokenForRequest();
        $user->removeToken($token);
    }

    protected function cycleRememberToken(AuthenticatableContract $user)
    {
        $user->setRememberToken($token = Str::random(60));

        $this->provider->updateRememberToken($user, $token);
    }
}
