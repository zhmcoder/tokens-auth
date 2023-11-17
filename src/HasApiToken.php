<?php

namespace Andruby\ApiToken;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Str;

trait HasApiToken
{
    public function genToken($user_id): string
    {
        $token = Str::random(60);

        if (config('tokens-auth.multi_login')) {
            $this->tokens()->create([
                'user_id' => $user_id,
                'api_token' => $token,
                'expire_at' => time() + config('tokens-auth.token_expire_time')
            ]);
            $this->resetToMaxActiveTokens();
        } else {
            $this->tokens()->updateOrCreate(['user_id' => $user_id], [
                'user_id' => $user_id,
                'api_token' => $token,
                'expire_at' => time() + config('tokens-auth.token_expire_time')
            ]);
        }
        return $token;
    }

    public function removeToken($token): void
    {
        $this->tokens()
            ->where('user_id', $this->getKey())
            ->where('api_token', $token)
            ->delete();
    }

    public function tokens(): HasMany
    {
        return $this->hasMany(ApiToken::class, 'user_id', 'id');
    }

    protected function resetToMaxActiveTokens(): void
    {
        $totalActiveTokens = config('tokens-auth.total_active_tokens');

        if ($totalActiveTokens !== null && $this->tokens()->count() > $totalActiveTokens) {
            $this->tokens()
                ->oldest()
                ->skip($totalActiveTokens)
                ->take($this->tokens()->count() - $totalActiveTokens)
                ->delete();
        }
    }
}
