<?php declare(strict_types=1);

namespace JWTMiddleware;

/**
 * A class meant to store claims stored in a JWT token.
 */
class UserToken
{
    /* The claims from the JWT */
    protected $claims;

    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    /**
     * @param string $key the name of the item to get from the claims
     * 
     * @return mixed a value from the claims, or null if one was not found
     */
    public function __get(string $key)
    {
        return $this->claims[$key] ?? null;
    }

    /**
     * @param string $key the name of the item to set in the claims
     * @param mixed $newValue the value for the key in the claims
     */
    public function __set(string $key, $newValue)
    {
        $this->claims[$key] = $newValue;
    }

    /**
     * Gets the current claims, with an updated expiration time.
     * 
     * @param int $newExpirationTime how many seconds the new token should be
     *                               valid for. Defaults to 1200 (20 minutes)
     */
    public function getNextClaims(int $newExpirationTime = 1200) : array
    {
        return array_merge($this->claims, ['exp' => $newExpirationTime]);
    }
}
