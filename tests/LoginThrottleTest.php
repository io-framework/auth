<?php

namespace Io\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Io\Auth\LoginThrottle;

final class LoginThrottleTest extends TestCase
{
    public function testAnAttemptCountsBeforeItIsChecked(): void
    {
        $throttle = new LoginThrottle();
        $allowed = 0;
        // Ten attempts "at once": each is counted the moment it is let through
        for ($i = 0; $i < 10; $i++) {
            $allowed += $throttle->attempt('203.0.113.9', 'ada@example.test') ? 1 : 0;
        }
        $this->assertSame(5, $allowed);
        // Another account from the same address still gets its own five
        $this->assertTrue($throttle->attempt('203.0.113.9', 'bo@example.test'));
    }

    public function testAnAddressAndAnAccountHaveLimitsOfTheirOwn(): void
    {
        $throttle = new LoginThrottle();
        for ($i = 0; $i < 20; $i++) {
            $throttle->attempt('203.0.113.9', "user$i@example.test");
        }
        $this->assertFalse($throttle->attempt('203.0.113.9', 'fresh@example.test'));

        // One account from many addresses: 50 in all, an IPv6 /64 counting as one address
        $throttle = new LoginThrottle();
        for ($i = 0; $i < 50; $i++) {
            $throttle->attempt("198.51.100.$i", 'ada@example.test');
        }
        $this->assertFalse($throttle->attempt('198.51.100.200', 'ada@example.test'));
        $throttle = new LoginThrottle();
        for ($i = 1; $i <= 5; $i++) {
            $throttle->attempt("2001:db8:1:2::$i", 'ada@example.test');
        }
        $this->assertFalse($throttle->attempt('2001:db8:1:2:ffff::1', 'ada@example.test'));
    }

    public function testSuccessClearsTheAccountButNotTheAddress(): void
    {
        $throttle = new LoginThrottle();
        for ($i = 0; $i < 4; $i++) {
            $throttle->attempt('203.0.113.9', 'ada@example.test');
        }
        $throttle->succeed('203.0.113.9', 'ada@example.test');
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($throttle->attempt('203.0.113.9', 'ada@example.test'));
        }
    }

    public function testLoginsThatSucceedNeverFillTheAddress(): void
    {
        // An office behind one address: thirty people log in
        $throttle = new LoginThrottle();
        for ($i = 0; $i < 30; $i++) {
            $this->assertTrue($throttle->attempt('203.0.113.9', "user$i@example.test"));
            $throttle->succeed('203.0.113.9', "user$i@example.test");
        }
    }
}
