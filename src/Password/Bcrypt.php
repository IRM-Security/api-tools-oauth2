<?php

declare(strict_types=1);

namespace Laminas\ApiTools\OAuth2\Password;

use InvalidArgumentException;

use function password_hash;
use function password_verify;
use function sprintf;

use const PASSWORD_BCRYPT;

/** Native bcrypt implementation; retain the existing OAuth2 cost and stored hash format. */
final class Bcrypt
{
    private int $cost = 10;

    public function setCost(int|string $cost): self
    {
        $cost = (int) $cost;
        if ($cost < 4 || $cost > 31) {
            throw new InvalidArgumentException('The bcrypt cost must be between 4 and 31.');
        }
        $this->cost = $cost;
        return $this;
    }

    public function getCost(): string
    {
        return sprintf('%02d', $this->cost);
    }

    public function create(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->cost]);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}
