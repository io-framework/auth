<?php

namespace Io\Auth;

use RuntimeException;

/** A change to users or roles that the rules forbid; $reason says which rule. */
final class AccountRefused extends RuntimeException
{
    public function __construct(public readonly Refusal $reason)
    {
        parent::__construct(match ($reason) {
            Refusal::EmailTaken => 'This email address has an account already',
            Refusal::RoleTaken => 'A role with this name exists already',
            Refusal::InvalidRoleName => 'A role needs a name of at most 60 characters',
            Refusal::UnknownRole => 'This role does not exist',
            Refusal::BuiltinRole => 'The Admin role always has every permission and asks for a second factor',
            Refusal::OwnAccount => 'Another admin changes your own account',
            Refusal::AdminOnly => 'Only an admin can change an admin',
            Refusal::LastAdmin => 'The site needs at least one active admin',
            Refusal::RoleTooStrong => 'This role allows more than you may do yourself',
        });
    }
}
