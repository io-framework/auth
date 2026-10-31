<?php

namespace Io\Auth;

use Data\Postgres;
use Io\Attributes\Inject;
use Io\Http\{Request, Response};
use Io\Support\Row;

/**
 * Sessions in the database, the cookie holds a random token: signing out, disabling a user or changing a role
 * counts from the next request on, which a signed token couldn't do. A session lasts AuthOptions::$idle after the
 * last request and $lifetime at most. Start one only once the login is complete, second factor included.
 */
final class Sessions
{
    #[Inject]
    private Postgres $db;

    #[Inject]
    private AuthOptions $options;

    #[Inject]
    private Viewer $viewer;

    public function start(int $userId, Request $req, Response $res): void
    {
        $token = bin2hex(random_bytes(32));
        $this->db->execute('DELETE FROM auth_sessions WHERE expires_at < now()');
        $this->db->execute(
            "INSERT INTO auth_sessions (token_hash, user_id, expires_at, user_agent)
             VALUES ($1, $2, now() + interval '1 second' * $3, $4)",
            [hash('sha256', $token), $userId, min($this->options->idle, $this->options->lifetime), substr($req->headers['User-Agent'] ?? '', 0, 300)],
        );
        $this->db->execute('UPDATE auth_users SET last_login_at = now() WHERE id = $1', [$userId]);
        $res->withCookie(
            $this->options->cookie,
            $token,
            maxAge: $this->options->remember ? $this->options->lifetime : null,
            secure: $this->hostOnly() ? true : null,
        );
    }

    /** The session of the request's cookie with what its roles allow now; null for none, an expired one or a disabled user. */
    public function find(Request $req): ?Principal
    {
        $token = $req->cookies[$this->options->cookie] ?? '';
        if ($token === '') {
            return null;
        }
        $row = $this->db->first(
            "SELECT s.id, s.user_id, s.last_seen_at < now() - interval '5 minutes' AS stale, u.handle,
                    coalesce(u.name, u.handle) AS name, u.email,
                    coalesce(bool_or(r.builtin), false) AS admin,
                    coalesce(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles,
                    coalesce(array_agg(DISTINCT rp.permission) FILTER (WHERE rp.permission IS NOT NULL), '{}') AS permissions
             FROM auth_sessions s
             JOIN auth_users u ON u.id = s.user_id AND u.disabled_at IS NULL
             LEFT JOIN auth_user_roles ur ON ur.user_id = u.id
             LEFT JOIN auth_roles r ON r.id = ur.role_id
             LEFT JOIN auth_role_permissions rp ON rp.role_id = r.id
             WHERE s.token_hash = $1 AND s.expires_at > now()
             GROUP BY s.id, u.id",
            [hash('sha256', $token)],
            as: Row::of(...),
        );
        if ($row === null) {
            return null;
        }
        // Written at most every 5 minutes, not on every request
        if ($row->bool('stale')) {
            $this->db->execute(
                "UPDATE auth_sessions SET last_seen_at = now(),
                    expires_at = least(created_at + interval '1 second' * $2, now() + interval '1 second' * $3)
                 WHERE id = $1",
                [$row->int('id'), $this->options->lifetime, $this->options->idle],
            );
        }

        return new Principal(
            $row->int('user_id'),
            $row->int('id'),
            $row->string('handle'),
            $row->string('name'),
            $row->string('email'),
            $row->list('roles', 'string'),
            $row->bool('admin'),
            $row->list('permissions', 'string'),
        );
    }

    /**
     * Signs the request in with its session: the Viewer knows the principal, and so does Io ($req->principal, for
     * #[Authenticated], #[Role] and #[Permissions]). A cookie the browser sends on its own: a #[SkipCsrf] route
     * ignores it.
     */
    public function signIn(Request $req): ?Principal
    {
        $principal = $this->find($req);
        $this->viewer->set($principal);
        $req->principal = $principal?->claims();
        $req->principalFromCookie = $principal !== null;

        return $principal;
    }

    /** Ends the request's session; without a response (over a WebSocket) the cookie stays, worth nothing then. */
    public function end(Request $req, ?Response $res = null): void
    {
        $token = $req->cookies[$this->options->cookie] ?? '';
        if ($token !== '') {
            $this->db->execute('DELETE FROM auth_sessions WHERE token_hash = $1', [hash('sha256', $token)]);
        }
        $res?->withCookie($this->options->cookie, '', maxAge: 0, secure: $this->hostOnly() ? true : null);
    }

    /** Signs the user out everywhere except in the session $keep: after a new password or second factor. */
    public function endOthers(int $userId, ?int $keep = null): int
    {
        return $this->db->execute('DELETE FROM auth_sessions WHERE user_id = $1 AND id IS DISTINCT FROM $2', [$userId, $keep]);
    }

    /** A __Host- or __Secure- cookie needs the Secure flag, or the browser drops it */
    private function hostOnly(): bool
    {
        return str_starts_with($this->options->cookie, '__Host-') || str_starts_with($this->options->cookie, '__Secure-');
    }
}
