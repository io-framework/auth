<?php

namespace Io\Auth;

/** How long a session lasts and which cookie carries it. Set with `$app->configure(fn (AuthOptions $auth) => ...)`. */
final class AuthOptions
{
    /**
     * The session cookie. A name starting with __Host- is only ever sent to this host, over HTTPS (or localhost), for
     * every path: no subdomain can set or read it.
     */
    public string $cookie = '__Host-session';

    /** Seconds a session lasts after its last request */
    public int $idle = 12 * 3600;

    /** Seconds a session lasts at most, however busy */
    public int $lifetime = 30 * 86400;

    /**
     * Seconds a connection that outlives its request (a WebSocket of io/live) keeps the user it opened with; then it
     * reconnects and the session is read again, which also keeps it from going idle. A session ended on purpose
     * (sign-out, new password, disabled user) closes such connections at once through Io's SignOuts.
     */
    public int $recheck = 300;

    /**
     * Whether the cookie outlives the browser (Max-Age is $lifetime); off, it ends with the browser session and the
     * server ends the session itself.
     */
    public bool $remember = false;

    /**
     * Whether users have a display name next to their handle. Off, the app's forms ask for none, Users keeps none,
     * and the handle stands in wherever a name is shown (Principal::$name, Account::$name).
     */
    public bool $displayName = true;
}
