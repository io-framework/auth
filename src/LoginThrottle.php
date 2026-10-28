<?php

namespace Io\Auth;

/**
 * Slows down guessing. An attempt counts before it is checked, so attempts sent at the same moment over several
 * connections can't slip past the count. Limits within 15 minutes: 5 for one account from one address, 20 from
 * one address in all, 50 for one account from anywhere. An IPv6 address counts by its /64, the block one
 * connection usually gets. Behind a proxy the site names it in Io's ProxyOptions, or every visitor shares
 * the proxy's address.
 *
 * ponytail: in the worker's memory, per worker; the database or Redis once a site runs several workers that must share it
 */
final class LoginThrottle
{
    private const array LIMITS = ['address' => 20, 'account' => 5, 'anywhere' => 50];
    private const int WINDOW = 900;

    /** @var array<string, array{int, int}> key => attempts, first attempt (unix time) */
    private array $attempts = [];

    /** Counts an attempt for $account (an email, or "2fa:<user>") from $ip; false if a limit was already reached. */
    public function attempt(string $ip, string $account): bool
    {
        $keys = $this->keys($ip, $account);
        foreach ($keys as $kind => $key) {
            if ($this->count($key) >= self::LIMITS[$kind]) {
                return false;
            }
        }
        if (count($this->attempts) > 10_000) {
            $this->attempts = array_filter($this->attempts, fn (array $entry) => $entry[1] > time() - self::WINDOW);
        }
        foreach ($keys as $key) {
            $this->attempts[$key] = [$this->count($key) + 1, $this->attempts[$key][1] ?? time()];
        }
        return true;
    }

    /** The account got in from this address: its own counts start over, and a success costs the address nothing. */
    public function succeed(string $ip, string $account): void
    {
        $keys = $this->keys($ip, $account);
        unset($this->attempts[$keys['account']], $this->attempts[$keys['anywhere']]);
        if ($this->count($keys['address']) > 0) {
            $this->attempts[$keys['address']][0]--;
        }
    }

    /** @return array{address: string, account: string, anywhere: string} */
    private function keys(string $ip, string $account): array
    {
        $packed = @inet_pton($ip);
        $address = $packed !== false && strlen($packed) === 16 ? bin2hex(substr($packed, 0, 8)) . '::/64' : $ip;
        $account = strtolower(trim($account));
        return ['address' => "address:$address", 'account' => "account:$address:$account", 'anywhere' => "anywhere:$account"];
    }

    private function count(string $key): int
    {
        $entry = $this->attempts[$key] ?? null;
        if ($entry === null || $entry[1] <= time() - self::WINDOW) {
            unset($this->attempts[$key]);
            return 0;
        }
        return $entry[0];
    }
}
