<?php

namespace Io\Auth;

use Io\Support\FiberLocal;

/** Who the current request belongs to: set by Sessions::signIn() (SessionMiddleware), null for a guest. */
final class Viewer
{
    /** @var FiberLocal<Principal|null> */
    private FiberLocal $principal;

    public function __construct()
    {
        $this->principal = new FiberLocal();
    }

    public function set(?Principal $principal): void
    {
        $this->principal->set($principal);
    }

    public function current(): ?Principal
    {
        $principal = $this->principal->get();

        return $principal instanceof Principal ? $principal : null;
    }
}
