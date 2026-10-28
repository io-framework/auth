<?php

namespace Io\Auth\Tests;

use Io\Auth\Totp;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    /** RFC 6238's SHA-1 key, "12345678901234567890", in base32 */
    private const string SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public function testTheCodesOfTheRfc(): void
    {
        $this->assertSame('287082', Totp::code(self::SECRET, intdiv(59, 30)));
        $this->assertSame('081804', Totp::code(self::SECRET, intdiv(1111111109, 30)));
    }

    public function testACodeFitsItsStepAndTheNeighboursButNotAnEarlierOneThanTheLast(): void
    {
        $now = 1_700_000_000;
        $step = intdiv($now, 30);

        $this->assertSame($step, Totp::verify(self::SECRET, Totp::code(self::SECRET, $step), $now));
        $this->assertSame($step - 1, Totp::verify(self::SECRET, Totp::code(self::SECRET, $step - 1), $now));
        $this->assertNull(Totp::verify(self::SECRET, Totp::code(self::SECRET, $step - 2), $now));
        $this->assertNull(Totp::verify(self::SECRET, Totp::code(self::SECRET, $step), $now, lastStep: $step));
        $this->assertNull(Totp::verify(self::SECRET, 'abcdef', $now));
    }

    public function testTheUriAnAppReads(): void
    {
        $this->assertSame(
            'otpauth://totp/Io%20Site:ada%40example.test?secret=' . self::SECRET . '&issuer=Io%20Site',
            Totp::uri(self::SECRET, 'ada@example.test', 'Io Site'),
        );
    }
}
