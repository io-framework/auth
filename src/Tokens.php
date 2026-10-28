<?php

namespace Io\Auth;

use Data\Postgres;
use Io\Attributes\Inject;
use Io\Support\Row;

/**
 * One-time tokens of a user by their kind: a password link, a login waiting for its second factor, a PIN for a
 * linked account. Only the hash is stored, a new token replaces the user's earlier one of the same kind, and a
 * disabled user's tokens count for nothing. One bound to a secret of the browser (a cookie) works only with it.
 */
final class Tokens
{
    #[Inject]
    private Postgres $db;

    /** A random token for $seconds; with $bind only redeem() with the same $bind takes it */
    public function issue(string $kind, int $userId, int $seconds, ?string $bind = null): string
    {
        $token = bin2hex(random_bytes(32));
        $this->replace($kind, $userId);
        $this->db->execute(
            "INSERT INTO auth_tokens (token_hash, user_id, kind, bound_hash, expires_at) VALUES ($1, $2, $3, $4, now() + interval '1 second' * $5)",
            [hash('sha256', $token), $userId, $kind, $bind === null ? null : hash('sha256', $bind), $seconds],
        );

        return $token;
    }

    /**
     * A PIN of eight digits as "1234-5678"; user() and redeem() take it with or without the dash. Short enough to
     * type, so it lives only briefly and the caller throttles the guesses.
     */
    public function pin(string $kind, int $userId, int $seconds): string
    {
        $this->replace($kind, $userId);
        do {
            $digits = sprintf('%08d', random_int(0, 99_999_999));
            // Another user's live PIN with the same digits: draw again
            $stored = $this->db->first(
                "INSERT INTO auth_tokens (token_hash, user_id, kind, expires_at) VALUES ($1, $2, $3, now() + interval '1 second' * $4)
                 ON CONFLICT (token_hash) DO NOTHING RETURNING user_id",
                [hash('sha256', $digits), $userId, $kind, $seconds],
            );
        } while ($stored === null);

        return substr($digits, 0, 4) . '-' . substr($digits, 4);
    }

    /** The user a valid token belongs to; the token stays */
    public function user(string $kind, string $token): ?int
    {
        return $this->db->first(
            'SELECT t.user_id FROM auth_tokens t JOIN auth_users u ON u.id = t.user_id AND u.disabled_at IS NULL
             WHERE t.token_hash = $1 AND t.kind = $2 AND t.expires_at > now()',
            [self::hash($token), $kind],
            as: fn (array $row): int => Row::of($row)->int('user_id'),
        );
    }

    /** The user a valid token belongs to, and the token is used up; a bound one only with its $bind */
    public function redeem(string $kind, string $token, ?string $bind = null): ?int
    {
        return $this->db->first(
            'DELETE FROM auth_tokens t USING auth_users u
             WHERE t.token_hash = $1 AND t.kind = $2 AND t.expires_at > now() AND u.id = t.user_id AND u.disabled_at IS NULL
                AND (t.bound_hash IS NULL OR t.bound_hash = $3)
             RETURNING t.user_id',
            [self::hash($token), $kind, $bind === null ? null : hash('sha256', $bind)],
            as: fn (array $row): int => Row::of($row)->int('user_id'),
        );
    }

    private function replace(string $kind, int $userId): void
    {
        $this->db->execute('DELETE FROM auth_tokens WHERE expires_at < now() OR (kind = $1 AND user_id = $2)', [$kind, $userId]);
    }

    /** A PIN counts by its digits */
    private static function hash(string $token): string
    {
        $digits = str_replace(['-', ' '], '', $token);

        return hash('sha256', ctype_digit($digits) && strlen($digits) === 8 ? $digits : $token);
    }
}
