<?php

namespace Io\Auth;

use DateTimeImmutable;
use Io\Support\Row;

/** A user as a list of users shows them. */
final readonly class Account
{
    /**
     * @param string $name the display name, or the handle when the site has none
     * @param list<int> $roles the ids of their roles
     */
    public function __construct(
        public int $id,
        public string $email,
        public string $handle,
        public string $name,
        public array $roles,
        public bool $admin,
        public bool $disabled,
        public bool $twoFactor,
        public bool $hasPassword,
        public ?DateTimeImmutable $lastLogin,
    ) {
    }

    /** @param array<string, mixed> $row */
    public static function from(array $row): self
    {
        $r = Row::of($row);
        $lastLogin = $r->nullableString('last_login_at');

        return new self(
            $r->int('id'),
            $r->string('email'),
            $r->string('handle'),
            $r->string('name'),
            $r->list('roles', 'int'),
            $r->bool('admin'),
            $r->bool('disabled'),
            $r->bool('two_factor'),
            $r->bool('has_password'),
            $lastLogin === null ? null : new DateTimeImmutable($lastLogin),
        );
    }
}
