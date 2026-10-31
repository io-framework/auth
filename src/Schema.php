<?php

namespace Io\Auth;

use Data\Postgres;
use Io\Support\Row;
use Transliterator;

/**
 * The tables, as steps for `Data\Migrations`: the app puts them before its own, so its tables can refer to auth_users.
 *
 *     new Migrations($db)->apply([...Schema::steps(), '001_posts' => '...']);
 */
final class Schema
{
    /** @return array<string, string|callable(Postgres): void> */
    public static function steps(): array
    {
        return ['auth_001_accounts' => self::ACCOUNTS, 'auth_002_handles' => self::handles(...)];
    }

    /**
     * Every user gets a handle and a unique display name. Existing users get one made from their name ("Zoë Kim"
     * becomes zoe_kim), with their id appended when it is too short or taken; a name that reads like an earlier
     * user's gets the id in brackets.
     */
    private static function handles(Postgres $tx): void
    {
        $tx->execute('ALTER TABLE auth_users ADD COLUMN handle text, ADD COLUMN name_key text, ALTER COLUMN name DROP NOT NULL');
        $ascii = Transliterator::create('Any-Latin; Latin-ASCII; Lower()');
        $handles = [];
        $keys = [];
        foreach ($tx->query('SELECT id, name FROM auth_users ORDER BY id', as: Row::of(...)) as $user) {
            $id = $user->int('id');
            $name = Users::name($user->string('name')) ?? "User $id";
            $slug = trim(preg_replace('/[^a-z0-9_-]+/', '_', (string) $ascii?->transliterate($name)) ?? '', '_-');
            $handle = Users::handle(substr($slug, 0, 32));
            if ($handle === null || isset($handles[$handle])) {
                $handle = Users::handle(substr($slug, 0, 31 - strlen((string) $id)) . "_$id") ?? "user_$id";
            }
            if (isset($keys[Users::nameKey($name)])) {
                $name = "$name ($id)";
            }
            $handles[$handle] = true;
            $keys[Users::nameKey($name)] = true;
            $tx->execute(
                'UPDATE auth_users SET handle = $2, name = $3, name_key = $4 WHERE id = $1',
                [$id, $handle, $name, Users::nameKey($name)],
            );
        }
        $tx->execute('ALTER TABLE auth_users ALTER COLUMN handle SET NOT NULL');
        $tx->execute('CREATE UNIQUE INDEX auth_users_handle ON auth_users (handle)');
        $tx->execute('CREATE UNIQUE INDEX auth_users_name_key ON auth_users (name_key)');
    }

    private const string ACCOUNTS = <<<'SQL'
        -- A user signs in with email and password; one without a password sets one through a link first
        CREATE TABLE auth_users (
            id bigserial PRIMARY KEY,
            email text NOT NULL,
            name text NOT NULL,
            password_hash text,
            totp_secret text,
            totp_enabled_at timestamptz,
            -- The time step last used: each code works once
            totp_last_step bigint,
            -- sha256 of each unused recovery code
            recovery_codes text[] NOT NULL DEFAULT '{}',
            disabled_at timestamptz,
            last_login_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE UNIQUE INDEX auth_users_email ON auth_users (lower(email));

        CREATE TABLE auth_roles (
            id bigserial PRIMARY KEY,
            name text NOT NULL UNIQUE,
            -- The Admin role: every permission, a second factor, never deleted
            builtin boolean NOT NULL DEFAULT false,
            two_factor_required boolean NOT NULL DEFAULT false,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        INSERT INTO auth_roles (name, builtin, two_factor_required) VALUES ('Admin', true, true);

        CREATE TABLE auth_role_permissions (
            role_id bigint NOT NULL REFERENCES auth_roles ON DELETE CASCADE,
            permission text NOT NULL,
            PRIMARY KEY (role_id, permission)
        );

        CREATE TABLE auth_user_roles (
            user_id bigint NOT NULL REFERENCES auth_users ON DELETE CASCADE,
            role_id bigint NOT NULL REFERENCES auth_roles ON DELETE CASCADE,
            PRIMARY KEY (user_id, role_id)
        );

        -- sha256 of the cookie's token: a database dump signs nobody in
        CREATE TABLE auth_sessions (
            id bigserial PRIMARY KEY,
            token_hash text NOT NULL UNIQUE,
            user_id bigint NOT NULL REFERENCES auth_users ON DELETE CASCADE,
            created_at timestamptz NOT NULL DEFAULT now(),
            last_seen_at timestamptz NOT NULL DEFAULT now(),
            expires_at timestamptz NOT NULL,
            user_agent text NOT NULL DEFAULT ''
        );
        CREATE INDEX auth_sessions_user ON auth_sessions (user_id);

        -- One-time tokens by their hash: a password link, a login waiting for its second factor, a PIN; bound_hash
        -- ties one to a secret of the browser it was issued to
        CREATE TABLE auth_tokens (
            token_hash text PRIMARY KEY,
            user_id bigint NOT NULL REFERENCES auth_users ON DELETE CASCADE,
            kind text NOT NULL,
            bound_hash text,
            expires_at timestamptz NOT NULL
        );
        CREATE INDEX auth_tokens_user ON auth_tokens (user_id, kind);
        SQL;
}
