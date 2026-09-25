<?php

namespace App\Services;

use App\Models\Playlist;
use Illuminate\Http\Client\Pool;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Throwable;

class ProviderAuthPassthroughService
{
    /**
     * Successful authentications are cached briefly so normal Xtream clients
     * do not hit the upstream provider on every API request.
     */
    private const AUTH_CACHE_TTL_SECONDS = 60;

    /**
     * Invalid credentials are cached for a few seconds to reduce repeated
     * upstream requests without making credential changes feel stale.
     */
    private const FAILED_AUTH_CACHE_TTL_SECONDS = 10;

    /**
     * Limit attempts against a single provider username.
     */
    private const USERNAME_RATE_LIMIT = 10;

    /**
     * Limit total uncached authentication attempts from one client IP.
     */
    private const IP_RATE_LIMIT = 120;

    private const RATE_LIMIT_DECAY_SECONDS = 60;

    /**
     * Keep provider authentication requests short. Fallback hosts are queried
     * in parallel after the primary fails, so the total delay does not grow
     * linearly with the number of fallback URLs.
     */
    private const HTTP_TIMEOUT_SECONDS = 4;

    private const HTTP_CONNECT_TIMEOUT_SECONDS = 2;

    /**
     * Find the single playlist currently configured for provider passthrough.
     */
    public function getEnabledPlaylist(): ?Playlist
    {
        return Playlist::query()
            ->where('provider_auth_passthrough', true)
            ->where('xtream', true)
            ->first();
    }

    /**
     * Authenticate credentials directly against the upstream Xtream provider.
     *
     * No plaintext username/password is stored in cache.
     *
     * @return array{
     *     playlist: Playlist,
     *     provider_url: string,
     *     user_info: array<string, mixed>
     * }|null
     */
    public function authenticate(
        string $username,
        string $password,
        ?string $clientIp = null
    ): ?array {
        $username = trim($username);

        if ($username === '' || $password === '') {
            return null;
        }

        $playlist = $this->getEnabledPlaylist();

        if (! $playlist) {
            return null;
        }

        $urls = $playlist->getOrderedXtreamUrls();

        if ($urls === []) {
            return null;
        }

        $cacheKey = $this->authCacheKey(
            $playlist,
            $username,
            $password,
            $urls
        );

        $cached = Cache::get($cacheKey);

        if (is_array($cached)) {
            if (($cached['valid'] ?? false) !== true) {
                return null;
            }

            if (
                ! isset($cached['provider_url']) ||
                ! isset($cached['user_info']) ||
                ! is_array($cached['user_info'])
            ) {
                Cache::forget($cacheKey);
            } else {
                return [
                    'playlist' => $playlist,
                    'provider_url' => $cached['provider_url'],
                    'user_info' => $cached['user_info'],
                ];
            }
        }

        $this->enforceRateLimit(
            $playlist,
            $username,
            $clientIp
        );

        $verify = ! ($playlist->disable_ssl_verification ?? false);

        $userAgent = $playlist->user_agent
            ?: 'VLC/3.0.21 LibVLC/3.0.21';

        /*
         * Try the primary URL first.
         *
         * If the primary explicitly says the credentials are invalid, there is
         * no reason to hammer every fallback host with the same bad password.
         */
        $primaryUrl = array_shift($urls);

        if ($primaryUrl !== null) {
            $primaryResult = $this->authenticateAgainstUrl(
                $primaryUrl,
                $username,
                $password,
                $userAgent,
                $verify
            );

            if ($primaryResult['state'] === 'valid') {
                $this->clearUsernameRateLimit($playlist, $username);

                return $this->cacheSuccessfulAuthentication(
                    $cacheKey,
                    $playlist,
                    $primaryResult['provider_url'],
                    $primaryResult['user_info']
                );
            }

            if ($primaryResult['state'] === 'invalid') {
                $this->cacheFailedAuthentication($cacheKey);

                return null;
            }

            if ($primaryResult['state'] === 'rate_limited') {
                throw new TooManyRequestsHttpException(
                    self::RATE_LIMIT_DECAY_SECONDS,
                    'The upstream provider is rate limiting authentication requests.'
                );
            }
        }

        /*
         * Primary host was unavailable/malformed.
         *
         * Try all fallback URLs in parallel rather than waiting sequentially
         * for N × timeout seconds.
         */
        if ($urls !== []) {
            $fallbackResult = $this->authenticateAgainstFallbacks(
                $urls,
                $username,
                $password,
                $userAgent,
                $verify
            );

            if ($fallbackResult !== null) {
                if ($fallbackResult['state'] === 'valid') {
                    $this->clearUsernameRateLimit($playlist, $username);

                    return $this->cacheSuccessfulAuthentication(
                        $cacheKey,
                        $playlist,
                        $fallbackResult['provider_url'],
                        $fallbackResult['user_info']
                    );
                }

                if ($fallbackResult['state'] === 'rate_limited') {
                    throw new TooManyRequestsHttpException(
                        self::RATE_LIMIT_DECAY_SECONDS,
                        'The upstream provider is rate limiting authentication requests.'
                    );
                }
            }
        }

        $this->cacheFailedAuthentication($cacheKey);

        return null;
    }

    /**
     * Authenticate against one Xtream server.
     *
     * @return array{
     *     state: 'valid'|'invalid'|'retryable'|'rate_limited',
     *     provider_url?: string,
     *     user_info?: array<string, mixed>
     * }
     */
    private function authenticateAgainstUrl(
        string $url,
        string $username,
        string $password,
        string $userAgent,
        bool $verify
    ): array {
        $providerUrl = $this->normalizeBaseUrl($url);

        if ($providerUrl === null) {
            return ['state' => 'retryable'];
        }

        try {
            $response = Http::connectTimeout(self::HTTP_CONNECT_TIMEOUT_SECONDS)
                ->timeout(self::HTTP_TIMEOUT_SECONDS)
                ->withOptions([
                    'verify' => $verify,
                ])
                ->withHeaders([
                    'User-Agent' => $userAgent,
                ])
                ->get(
                    "{$providerUrl}/player_api.php",
                    [
                        'username' => $username,
                        'password' => $password,
                    ]
                );
        } catch (Throwable) {
            return ['state' => 'retryable'];
        }

        return $this->classifyResponse(
            $response,
            $providerUrl
        );
    }

    /**
     * Authenticate against fallback URLs concurrently.
     *
     * @param  array<int, string>  $urls
     * @return array{
     *     state: 'valid'|'invalid'|'retryable'|'rate_limited',
     *     provider_url?: string,
     *     user_info?: array<string, mixed>
     * }|null
     */
    private function authenticateAgainstFallbacks(
        array $urls,
        string $username,
        string $password,
        string $userAgent,
        bool $verify
    ): ?array {
        $normalizedUrls = [];

        foreach ($urls as $index => $url) {
            $normalized = $this->normalizeBaseUrl($url);

            if ($normalized !== null) {
                $normalizedUrls["provider_{$index}"] = $normalized;
            }
        }

        if ($normalizedUrls === []) {
            return null;
        }

        try {
            $responses = Http::pool(
                function (Pool $pool) use (
                    $normalizedUrls,
                    $username,
                    $password,
                    $userAgent,
                    $verify
                ): array {
                    $requests = [];

                    foreach ($normalizedUrls as $key => $providerUrl) {
                        $requests[] = $pool
                            ->as($key)
                            ->connectTimeout(self::HTTP_CONNECT_TIMEOUT_SECONDS)
                            ->timeout(self::HTTP_TIMEOUT_SECONDS)
                            ->withOptions([
                                'verify' => $verify,
                            ])
                            ->withHeaders([
                                'User-Agent' => $userAgent,
                            ])
                            ->get(
                                "{$providerUrl}/player_api.php",
                                [
                                    'username' => $username,
                                    'password' => $password,
                                ]
                            );
                    }

                    return $requests;
                }
            );
        } catch (Throwable) {
            return null;
        }

        $sawRateLimit = false;
        $sawInvalidCredentials = false;

        /*
         * Iterate in configured URL priority order even though the requests ran
         * concurrently.
         */
        foreach ($normalizedUrls as $key => $providerUrl) {
            $response = $responses[$key] ?? null;

            if (! $response instanceof Response) {
                continue;
            }

            $result = $this->classifyResponse(
                $response,
                $providerUrl
            );

            if ($result['state'] === 'valid') {
                return $result;
            }

            if ($result['state'] === 'rate_limited') {
                $sawRateLimit = true;
            }

            if ($result['state'] === 'invalid') {
                $sawInvalidCredentials = true;
            }
        }

        if ($sawRateLimit) {
            return ['state' => 'rate_limited'];
        }

        if ($sawInvalidCredentials) {
            return ['state' => 'invalid'];
        }

        return ['state' => 'retryable'];
    }

    /**
     * Classify an upstream Xtream authentication response.
     *
     * Raw provider account fields are never returned directly. The user_info
     * object is normalized before it can be consumed elsewhere in the app.
     *
     * @return array{
     *     state: 'valid'|'invalid'|'retryable'|'rate_limited',
     *     provider_url?: string,
     *     user_info?: array<string, mixed>
     * }
     */
    private function classifyResponse(
        Response $response,
        string $providerUrl
    ): array {
        if ($response->status() === 429) {
            return ['state' => 'rate_limited'];
        }

        if (in_array($response->status(), [401, 403], true)) {
            return ['state' => 'invalid'];
        }

        if (! $response->successful()) {
            return ['state' => 'retryable'];
        }

        $data = $response->json();

        if (! is_array($data)) {
            return ['state' => 'retryable'];
        }

        $userInfo = $data['user_info'] ?? null;

        if (! is_array($userInfo)) {
            return ['state' => 'retryable'];
        }

        $normalizedUserInfo = $this->normalizeUserInfo($userInfo);

        if ($normalizedUserInfo === null) {
            return ['state' => 'invalid'];
        }

        return [
            'state' => 'valid',
            'provider_url' => $providerUrl,
            'user_info' => $normalizedUserInfo,
        ];
    }

    /**
     * Validate and normalize account information returned by the provider.
     *
     * @return array<string, mixed>|null
     */
    private function normalizeUserInfo(array $userInfo): ?array
    {
        $authenticated = in_array(
            $userInfo['auth'] ?? null,
            [1, '1', true],
            true
        );

        if (! $authenticated) {
            return null;
        }

        $status = strtolower(
            trim((string) ($userInfo['status'] ?? 'active'))
        );

        if ($status !== 'active') {
            return null;
        }

        $expDate = $this->normalizeTimestamp(
            $userInfo['exp_date'] ?? null
        );

        if (
            $expDate !== null &&
            (int) $expDate <= time()
        ) {
            return null;
        }

        $createdAt = $this->normalizeTimestamp(
            $userInfo['created_at'] ?? null
        );

        $isTrial = in_array(
            $userInfo['is_trial'] ?? null,
            [1, '1', true, 'true'],
            true
        );

        $activeConnections = $this->normalizeUnsignedInteger(
            $userInfo['active_cons'] ?? 0
        );

        $maxConnections = $this->normalizeUnsignedInteger(
            $userInfo['max_connections'] ?? 0
        );

        $allowedFormats = $this->normalizeOutputFormats(
            $userInfo['allowed_output_formats'] ?? []
        );

        return [
            'auth' => 1,
            'status' => 'Active',
            'exp_date' => $expDate,
            'is_trial' => $isTrial ? '1' : '0',
            'active_cons' => (string) $activeConnections,
            'created_at' => $createdAt,
            'max_connections' => (string) $maxConnections,
            'allowed_output_formats' => $allowedFormats,
        ];
    }

    /**
     * @return array<int, string>
     */
    private function normalizeOutputFormats(mixed $formats): array
    {
        if (! is_array($formats)) {
            return ['ts', 'm3u8'];
        }

        $allowed = [
            'ts',
            'm3u8',
            'rtmp',
        ];

        $normalized = [];

        foreach ($formats as $format) {
            if (! is_string($format)) {
                continue;
            }

            $format = strtolower(trim($format));

            if (
                in_array($format, $allowed, true) &&
                ! in_array($format, $normalized, true)
            ) {
                $normalized[] = $format;
            }
        }

        return $normalized !== []
            ? $normalized
            : ['ts', 'm3u8'];
    }

    private function normalizeTimestamp(mixed $value): ?string
    {
        if (
            ! is_numeric($value) ||
            (int) $value <= 0
        ) {
            return null;
        }

        return (string) ((int) $value);
    }

    private function normalizeUnsignedInteger(mixed $value): int
    {
        if (! is_numeric($value)) {
            return 0;
        }

        return max(0, (int) $value);
    }

    private function normalizeBaseUrl(string $url): ?string
    {
        $url = trim($url);

        if ($url === '') {
            return null;
        }

        if (! Str::startsWith($url, ['http://', 'https://'])) {
            $url = 'http://'.$url;
        }

        return rtrim(
            str_replace(' ', '%20', $url),
            '/'
        );
    }

    /**
     * Protect the provider against credential probing.
     */
    private function enforceRateLimit(
        Playlist $playlist,
        string $username,
        ?string $clientIp
    ): void {
        $usernameKey = $this->usernameRateLimitKey(
            $playlist,
            $username
        );

        if (
            RateLimiter::tooManyAttempts(
                $usernameKey,
                self::USERNAME_RATE_LIMIT
            )
        ) {
            throw new TooManyRequestsHttpException(
                RateLimiter::availableIn($usernameKey),
                'Too many authentication attempts for this username.'
            );
        }

        $ipKey = $this->ipRateLimitKey(
            $playlist,
            $clientIp
        );

        if (
            RateLimiter::tooManyAttempts(
                $ipKey,
                self::IP_RATE_LIMIT
            )
        ) {
            throw new TooManyRequestsHttpException(
                RateLimiter::availableIn($ipKey),
                'Too many authentication attempts from this address.'
            );
        }

        RateLimiter::hit(
            $usernameKey,
            self::RATE_LIMIT_DECAY_SECONDS
        );

        RateLimiter::hit(
            $ipKey,
            self::RATE_LIMIT_DECAY_SECONDS
        );
    }

    private function clearUsernameRateLimit(
        Playlist $playlist,
        string $username
    ): void {
        RateLimiter::clear(
            $this->usernameRateLimitKey(
                $playlist,
                $username
            )
        );
    }

    private function cacheSuccessfulAuthentication(
        string $cacheKey,
        Playlist $playlist,
        string $providerUrl,
        array $userInfo
    ): array {
        Cache::put(
            $cacheKey,
            [
                'valid' => true,
                'provider_url' => $providerUrl,
                'user_info' => $userInfo,
            ],
            now()->addSeconds(self::AUTH_CACHE_TTL_SECONDS)
        );

        return [
            'playlist' => $playlist,
            'provider_url' => $providerUrl,
            'user_info' => $userInfo,
        ];
    }

    private function cacheFailedAuthentication(
        string $cacheKey
    ): void {
        Cache::put(
            $cacheKey,
            [
                'valid' => false,
            ],
            now()->addSeconds(self::FAILED_AUTH_CACHE_TTL_SECONDS)
        );
    }

    /**
     * The password is never included literally in a cache key.
     *
     * @param  array<int, string>  $urls
     */
    private function authCacheKey(
        Playlist $playlist,
        string $username,
        string $password,
        array $urls
    ): string {
        $credentialHash = hash_hmac(
            'sha256',
            mb_strtolower($username)."\0".$password,
            $this->hashSecret()
        );

        $providerHash = hash(
            'sha256',
            implode('|', $urls)
        );

        return sprintf(
            'provider-auth-passthrough:%d:%s:%s',
            $playlist->id,
            $providerHash,
            $credentialHash
        );
    }

    private function usernameRateLimitKey(
        Playlist $playlist,
        string $username
    ): string {
        $usernameHash = hash_hmac(
            'sha256',
            mb_strtolower(trim($username)),
            $this->hashSecret()
        );

        return sprintf(
            'provider-auth-passthrough:username:%d:%s',
            $playlist->id,
            $usernameHash
        );
    }

    private function ipRateLimitKey(
        Playlist $playlist,
        ?string $clientIp
    ): string {
        $ipHash = hash_hmac(
            'sha256',
            $clientIp ?: 'unknown',
            $this->hashSecret()
        );

        return sprintf(
            'provider-auth-passthrough:ip:%d:%s',
            $playlist->id,
            $ipHash
        );
    }

    private function hashSecret(): string
    {
        $key = (string) config('app.key');

        return $key !== ''
            ? $key
            : self::class;
    }
}
