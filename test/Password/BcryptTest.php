<?php

declare(strict_types=1);

namespace LaminasTest\ApiTools\OAuth2\Password;

use InvalidArgumentException;
use Laminas\ApiTools\OAuth2\Password\Bcrypt;
use PHPUnit\Framework\TestCase;

use function password_get_info;

final class BcryptTest extends TestCase
{
    public function testExistingHashesAndDefaultCostArePreserved(): void
    {
        $bcrypt = new Bcrypt();
        $hash = $bcrypt->create('compatibility-password');
        self::assertSame('10', $bcrypt->getCost());
        self::assertSame(10, password_get_info($hash)['options']['cost']);
        self::assertTrue($bcrypt->verify('compatibility-password', $hash));
        self::assertFalse($bcrypt->verify('wrong-password', $hash));
        // Fixed hash produced by PHP bcrypt; compatible with the previous Laminas wrapper.
        self::assertTrue($bcrypt->verify(
            'legacy-oauth-password',
            '$2y$10$VO0hLYqkGX.fKTdZu9QfP.k.GAEKGQ1aRryCYlzmq2o5OdW9pW1fi'
        ));
    }

    public function testConfiguredCostIsUsed(): void
    {
        $bcrypt = (new Bcrypt())->setCost('04');
        self::assertSame('04', $bcrypt->getCost());
        self::assertSame(4, password_get_info($bcrypt->create('password'))['options']['cost']);
    }

    public function testInvalidCostIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new Bcrypt())->setCost(3);
    }
}
