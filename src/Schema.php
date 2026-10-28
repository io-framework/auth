<?php

namespace Io\Auth;

/**
 * The tables, as steps for `Data\Migrations`: the app puts them before its own, so its tables can refer to auth_users.
 *
 *     new Migrations($db)->apply([...Schema::steps(), '001_posts' => '...']);
 */
final class Schema
{
    /** @return array<string, string> */
    public static function steps(): array
    {
        return ['auth_001_accounts' => self::ACCOUNTS];
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
