<?php

namespace Io\Auth;

use Io\Attributes\Inject;
use Io\Http\{MiddlewareBase, Request, Response};

/** Signs every request in with its session cookie: `$app->use($app->get(SessionMiddleware::class))`. */
final class SessionMiddleware extends MiddlewareBase
{
    #[Inject]
    private Sessions $sessions;

    protected function before(Request $req, Response $res): bool
    {
        $this->sessions->signIn($req);

        return true;
    }
}
