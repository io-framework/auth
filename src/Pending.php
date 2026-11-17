<?php

namespace Io\Auth;

/** What a user must do at sign-in before a session starts (Users::pending()), in this order. */
final readonly class Pending
{
    public function __construct(
        /** A new password: the current one was handed over by someone else */
        public bool $passwordChange,
        /** A second factor to set up: asked for, or a role needs one */
        public bool $twoFactorSetup,
    ) {
    }

    /** Nothing left: the session may start */
    public function none(): bool
    {
        return !$this->passwordChange && !$this->twoFactorSetup;
    }
}
