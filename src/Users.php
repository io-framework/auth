<?php

namespace Io\Auth;

use Data\Postgres;
use Io\Attributes\Inject;
use Io\Support\Row;
use Normalizer;
use Spoofchecker;

/**
 * The users: their passwords, second factor and roles, and the rules for changing someone else's account. Each has a
 * handle for addresses like /u/kakashi and, unless AuthOptions::$displayName is off, a display name; both are unique.
 */
final class Users
{
    /** Argon2id: no 72-byte limit like bcrypt, and costly to guess on graphics cards */
    private const string ALGORITHM = PASSWORD_ARGON2ID;

    /** Lower-case ASCII letters, digits, _ and -: the same in every address bar and font */
    private const string HANDLE = '/^[a-z0-9_-]{3,32}$/';

    /** Characters at most in a display name */
    private const int NAME_LENGTH = 60;

    /** An account with its roles, as Account::from() reads it; without a display name, the handle stands in */
    private const string ACCOUNT = "SELECT u.id, u.email, u.handle, coalesce(u.name, u.handle) AS name,
            u.disabled_at IS NOT NULL AS disabled,
            u.totp_enabled_at IS NOT NULL AS two_factor, u.password_hash IS NOT NULL AS has_password, u.last_login_at,
            coalesce(array_agg(ur.role_id ORDER BY ur.role_id) FILTER (WHERE ur.role_id IS NOT NULL), '{}') AS roles,
            coalesce(bool_or(r.builtin), false) AS admin
        FROM auth_users u LEFT JOIN auth_user_roles ur ON ur.user_id = u.id LEFT JOIN auth_roles r ON r.id = ur.role_id";

    #[Inject]
    private Postgres $db;

    #[Inject]
    private AuthOptions $options;

    /** Verified when the email is unknown, so the answer takes as long as for a wrong password */
    private static ?string $dummyHash = null;

    public function count(): int
    {
        return Row::of($this->db->first('SELECT count(*)::int AS n FROM auth_users') ?? [])->int('n');
    }

    public function find(int $id): ?Account
    {
        return $this->db->first(self::ACCOUNT . ' WHERE u.id = $1 GROUP BY u.id', [$id], as: Account::from(...));
    }

    public function byEmail(string $email): ?Account
    {
        return $this->db->first(self::ACCOUNT . ' WHERE lower(u.email) = lower($1) GROUP BY u.id', [trim($email)], as: Account::from(...));
    }

    /** @return list<Account> the active ones first, by name */
    public function all(): array
    {
        return $this->db->query(self::ACCOUNT . ' GROUP BY u.id ORDER BY u.disabled_at IS NOT NULL, lower(coalesce(u.name, u.handle))', as: Account::from(...));
    }

    public function byHandle(string $handle): ?Account
    {
        return $this->db->first(self::ACCOUNT . ' WHERE u.handle = lower($1) GROUP BY u.id', [trim($handle)], as: Account::from(...));
    }

    public function emailTaken(string $email, ?int $except = null): bool
    {
        return $this->db->first('SELECT 1 FROM auth_users WHERE lower(email) = lower($1) AND id IS DISTINCT FROM $2', [trim($email), $except]) !== null;
    }

    public function handleTaken(string $handle, ?int $except = null): bool
    {
        return $this->db->first('SELECT 1 FROM auth_users WHERE handle = lower($1) AND id IS DISTINCT FROM $2', [trim($handle), $except]) !== null;
    }

    /** Whether another user has a display name that reads the same: "Kakashi", "kakashi" and "KAKASHI" do */
    public function nameTaken(string $name, ?int $except = null): bool
    {
        $name = self::name($name);
        if ($name === null) {
            return false;
        }

        return $this->db->first('SELECT 1 FROM auth_users WHERE name_key = $1 AND id IS DISTINCT FROM $2', [self::nameKey($name), $except]) !== null;
    }

    /**
     * A new user; without a password they set one through a link first. With $by, the roles are checked against what
     * $by may hand out; without, the app vouches for them. $name is left out when AuthOptions::$displayName is off.
     *
     * @param list<int> $roles
     */
    public function create(
        string $email,
        string $handle,
        ?string $name = null,
        ?string $password = null,
        array $roles = [],
        ?Principal $by = null,
    ): int {
        [$handle, $name] = $this->identity($handle, $name);

        return $this->db->transaction(function (Postgres $tx) use ($email, $handle, $name, $password, $roles, $by): int {
            if ($by !== null) {
                $this->assignable($tx, $by, $roles);
            }
            $id = $this->insert($tx, $email, $handle, $name, $password === null ? null : self::hash($password));
            $this->assign($tx, $id, $roles);

            return $id;
        });
    }

    /** The first user of a site, an admin; null when someone was faster: two tabs on a new site never make two. */
    public function createFirstAdmin(string $email, string $handle, string $password, ?string $name = null): ?int
    {
        [$handle, $name] = $this->identity($handle, $name);

        return $this->db->transaction(function (Postgres $tx) use ($email, $handle, $name, $password): ?int {
            $tx->execute('LOCK TABLE auth_users IN EXCLUSIVE MODE');
            if (Row::of($tx->first('SELECT count(*)::int AS n FROM auth_users') ?? [])->int('n') > 0) {
                return null;
            }
            $id = $this->insert($tx, $email, $handle, $name, self::hash($password));
            $tx->execute('INSERT INTO auth_user_roles (user_id, role_id) SELECT $1, id FROM auth_roles WHERE builtin', [$id]);

            return $id;
        });
    }

    /** The user's id when email and password fit an active user; null otherwise, in about the same time. */
    public function authenticate(string $email, string $password): ?int
    {
        $user = $this->db->first(
            'SELECT id, password_hash FROM auth_users WHERE lower(email) = lower($1) AND disabled_at IS NULL',
            [trim($email)],
            as: Row::of(...),
        );
        $hash = $user?->nullableString('password_hash') ?? self::dummy();
        if (!password_verify($password, $hash) || $user === null) {
            return null;
        }
        if (password_needs_rehash($hash, self::ALGORITHM)) {
            $this->setPassword($user->int('id'), $password);
        }

        return $user->int('id');
    }

    /** Whether $password is the user's own, for changes that ask for it again */
    public function checkPassword(int $id, string $password): bool
    {
        $hash = $this->db->first(
            'SELECT password_hash FROM auth_users WHERE id = $1',
            [$id],
            as: fn (array $row): ?string => Row::of($row)->nullableString('password_hash'),
        );

        return password_verify($password, $hash ?? self::dummy()) && $hash !== null;
    }

    public function setPassword(int $id, string $password): void
    {
        $this->db->execute('UPDATE auth_users SET password_hash = $2 WHERE id = $1', [$id, self::hash($password)]);
    }

    /** The user's own email, handle and display name; refused when another account has one of them */
    public function update(int $id, string $email, string $handle, ?string $name = null): void
    {
        [$handle, $name] = $this->identity($handle, $name);
        $this->db->transaction(function (Postgres $tx) use ($id, $email, $handle, $name): void {
            $refusal = self::taken($tx, $email, $handle, $name, $id);
            if ($refusal !== null) {
                throw new AccountRefused($refusal);
            }
            $tx->execute(
                'UPDATE auth_users SET email = $2, handle = $3, name = $4, name_key = $5 WHERE id = $1',
                [$id, trim($email), $handle, $name, $name === null ? null : self::nameKey($name)],
            );
        });
    }

    /** The handle as it is kept (trimmed, lower case); null when it isn't 3 to 32 of a-z, 0-9, _ and - */
    public static function handle(string $handle): ?string
    {
        $handle = strtolower(trim($handle));

        return preg_match(self::HANDLE, $handle) === 1 ? $handle : null;
    }

    /**
     * The display name as it is kept: NFKC, spaces collapsed. Null when it is empty, longer than 60 characters, holds
     * control or invisible characters, or mixes scripts the way a look-alike does ("Kakashi" with a Cyrillic а);
     * Latin with Japanese, Chinese or Korean is fine.
     */
    public static function name(string $name): ?string
    {
        $name = Normalizer::normalize($name, Normalizer::FORM_KC);
        if ($name === false || preg_match('/[\p{Cc}\p{Cf}]/u', $name) === 1) {
            return null;
        }
        $name = trim(preg_replace('/\s+/u', ' ', $name) ?? '');
        if ($name === '' || mb_strlen($name) > self::NAME_LENGTH) {
            return null;
        }
        $checker = new Spoofchecker();
        $checker->setChecks(Spoofchecker::SINGLE_SCRIPT | Spoofchecker::INVISIBLE | Spoofchecker::MIXED_NUMBERS);
        $checker->setRestrictionLevel(Spoofchecker::HIGHLY_RESTRICTIVE);

        return $checker->isSuspicious($name) ? null : $name;
    }

    /**
     * What makes two display names the same: case folded, so the unique index on name_key refuses "KAKASHI" next to
     * "Kakashi". Names of a single script can't hide a look-alike letter; name() refuses the mixes.
     */
    public static function nameKey(string $name): string
    {
        return (string) Normalizer::normalize($name, Normalizer::FORM_KC_CF);
    }

    /**
     * The handle and display name as they are kept, or the refusal; without display names, the name is null.
     *
     * @return array{string, ?string}
     */
    private function identity(string $handle, ?string $name): array
    {
        $handle = self::handle($handle) ?? throw new AccountRefused(Refusal::InvalidHandle);
        if (!$this->options->displayName) {
            return [$handle, null];
        }

        return [$handle, self::name($name ?? '') ?? throw new AccountRefused(Refusal::InvalidName)];
    }

    /** Inserts the user; a taken email, handle or name is refused, also when another request was faster */
    private function insert(Postgres $tx, string $email, string $handle, ?string $name, ?string $passwordHash): int
    {
        $refusal = self::taken($tx, $email, $handle, $name);
        if ($refusal !== null) {
            throw new AccountRefused($refusal);
        }
        $id = $tx->first(
            'INSERT INTO auth_users (email, handle, name, name_key, password_hash) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT DO NOTHING RETURNING id',
            [trim($email), $handle, $name, $name === null ? null : self::nameKey($name), $passwordHash],
            as: fn (array $row): int => Row::of($row)->int('id'),
        );

        return $id ?? throw new AccountRefused(self::taken($tx, $email, $handle, $name) ?? Refusal::EmailTaken);
    }

    /** Which of email, handle and display name another user has, the first one found; null for none */
    private static function taken(Postgres $db, string $email, string $handle, ?string $name, ?int $except = null): ?Refusal
    {
        $row = $db->first(
            'SELECT bool_or(lower(email) = lower($1)) AS email, bool_or(handle = $2) AS handle, bool_or(name_key = $3) AS name
             FROM auth_users WHERE (lower(email) = lower($1) OR handle = $2 OR name_key = $3) AND id IS DISTINCT FROM $4',
            [trim($email), $handle, $name === null ? null : self::nameKey($name), $except],
            as: Row::of(...),
        );

        return match (true) {
            $row?->nullableBool('email') === true => Refusal::EmailTaken,
            $row?->nullableBool('handle') === true => Refusal::HandleTaken,
            $row?->nullableBool('name') === true => Refusal::NameTaken,
            default => null,
        };
    }

    /**
     * The user's roles, in place of the ones they had.
     *
     * @param list<int> $roles
     */
    public function setRoles(Principal $by, int $id, array $roles): void
    {
        $this->change($by, $id, function (Postgres $tx) use ($by, $id, $roles): void {
            $current = $tx->query('SELECT role_id FROM auth_user_roles WHERE user_id = $1', [$id], as: fn (array $row): int => Row::of($row)->int('role_id'));
            // Taking a role away needs the same right as giving it
            $this->assignable($tx, $by, array_values(array_diff($roles, $current)));
            $this->assignable($tx, $by, array_values(array_diff($current, $roles)));
            $tx->execute('DELETE FROM auth_user_roles WHERE user_id = $1', [$id]);
            $this->assign($tx, $id, $roles);
        });
    }

    /** A disabled user can't sign in, and their sessions and tokens end now */
    public function setDisabled(Principal $by, int $id, bool $disabled): void
    {
        $this->change($by, $id, function (Postgres $tx) use ($id, $disabled): void {
            $tx->execute('UPDATE auth_users SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) END WHERE id = $1', [$id, $disabled]);
            if ($disabled) {
                $tx->execute('DELETE FROM auth_sessions WHERE user_id = $1', [$id]);
                $tx->execute('DELETE FROM auth_tokens WHERE user_id = $1', [$id]);
            }
        });
    }

    /** For a lost phone: the second factor is gone, and so are the user's sessions */
    public function resetTwoFactor(Principal $by, int $id): void
    {
        $this->change($by, $id, function (Postgres $tx) use ($id): void {
            $this->clearTwoFactor($tx, $id);
            $tx->execute('DELETE FROM auth_sessions WHERE user_id = $1', [$id]);
        });
    }

    /** Whether $by may change the user $id at all: never their own account, and only an admin changes an admin */
    public function mayChange(Principal $by, int $id): bool
    {
        return $by->id !== $id && ($by->admin || $this->find($id)?->admin === false);
    }

    /** @return array{enabled: bool, required: bool} whether the user has a second factor, and whether a role asks for one */
    public function twoFactor(int $id): array
    {
        $row = Row::of($this->db->first(
            'SELECT u.totp_enabled_at IS NOT NULL AS enabled, coalesce(bool_or(r.two_factor_required), false) AS required
             FROM auth_users u LEFT JOIN auth_user_roles ur ON ur.user_id = u.id LEFT JOIN auth_roles r ON r.id = ur.role_id
             WHERE u.id = $1 GROUP BY u.id',
            [$id],
        ) ?? ['enabled' => false, 'required' => false]);

        return ['enabled' => $row->bool('enabled'), 'required' => $row->bool('required')];
    }

    /**
     * Turns the second factor on with $secret, which the user's app just proved with $code, and keeps the recovery
     * codes; false when the code doesn't fit or the user has a second factor already. With $replace, a new app takes
     * the old one's place: its secret and codes stop working.
     *
     * @param list<string> $recoveryCodes
     */
    public function enableTwoFactor(int $id, string $secret, string $code, array $recoveryCodes, bool $replace = false): bool
    {
        $step = Totp::verify($secret, $code, time());
        if ($step === null) {
            return false;
        }

        return $this->db->execute(
            'UPDATE auth_users SET totp_secret = $2, totp_enabled_at = now(), totp_last_step = $3, recovery_codes = $4::text[]
             WHERE id = $1 AND ($5 OR totp_enabled_at IS NULL)',
            [$id, $secret, $step, array_map(self::recoveryHash(...), $recoveryCodes), $replace],
        ) === 1;
    }

    public function disableTwoFactor(int $id): void
    {
        $this->clearTwoFactor($this->db, $id);
    }

    /**
     * New recovery codes in place of the old ones, for a user with a second factor.
     *
     * @param list<string> $recoveryCodes
     */
    public function replaceRecoveryCodes(int $id, array $recoveryCodes): bool
    {
        return $this->db->execute(
            'UPDATE auth_users SET recovery_codes = $2::text[] WHERE id = $1 AND totp_enabled_at IS NOT NULL',
            [$id, array_map(self::recoveryHash(...), $recoveryCodes)],
        ) === 1;
    }

    /** A code from the app, each time step once, or one of the recovery codes, which is then used up */
    public function verifySecondFactor(int $id, string $code): bool
    {
        $user = $this->db->first('SELECT totp_secret, totp_last_step FROM auth_users WHERE id = $1 AND totp_enabled_at IS NOT NULL', [$id], as: Row::of(...));
        $secret = $user?->nullableString('totp_secret');
        if ($user === null || $secret === null) {
            return false;
        }
        $step = Totp::verify($secret, $code, time(), $user->nullableInt('totp_last_step'));
        if ($step !== null) {
            // Only one request wins a step: the same code twice at the same moment signs in once
            return $this->db->execute(
                'UPDATE auth_users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)',
                [$id, $step],
            ) === 1;
        }

        return $this->db->execute(
            'UPDATE auth_users SET recovery_codes = array_remove(recovery_codes, $2) WHERE id = $1 AND $2 = ANY (recovery_codes)',
            [$id, self::recoveryHash($code)],
        ) === 1;
    }

    /** @return list<string> ten new recovery codes like "k3x9p-2mfa7", shown once; only their hashes are kept */
    public static function recoveryCodes(): array
    {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $code = substr(strtolower(Totp::secret()), 0, 10);
            $codes[] = substr($code, 0, 5) . '-' . substr($code, 5);
        }

        return $codes;
    }

    /**
     * Runs $work on someone else's account in a transaction that keeps at least one active admin: two admins taking
     * each other's role at the same time leave one.
     *
     * @param callable(Postgres): void $work
     */
    private function change(Principal $by, int $id, callable $work): void
    {
        if ($by->id === $id) {
            throw new AccountRefused(Refusal::OwnAccount);
        }
        if (!$this->mayChange($by, $id)) {
            throw new AccountRefused(Refusal::AdminOnly);
        }
        $this->db->transaction(function (Postgres $tx) use ($work): void {
            $tx->execute('LOCK TABLE auth_user_roles IN SHARE ROW EXCLUSIVE MODE');
            $work($tx);
            $admins = Row::of($tx->first(
                'SELECT count(DISTINCT u.id)::int AS n FROM auth_users u
                 JOIN auth_user_roles ur ON ur.user_id = u.id JOIN auth_roles r ON r.id = ur.role_id AND r.builtin
                 WHERE u.disabled_at IS NULL',
            ) ?? [])->int('n');
            if ($admins === 0) {
                throw new AccountRefused(Refusal::LastAdmin);
            }
        });
    }

    /**
     * That $by may hand out (or take away) $roles: an admin any, others only roles that allow no more than they may
     * do themselves, and never the Admin role.
     *
     * @param list<int> $roles
     */
    private function assignable(Postgres $tx, Principal $by, array $roles): void
    {
        if ($by->admin || $roles === []) {
            return;
        }
        $rows = $tx->query(
            "SELECT r.builtin, coalesce(array_agg(rp.permission) FILTER (WHERE rp.permission IS NOT NULL), '{}') AS permissions
             FROM auth_roles r LEFT JOIN auth_role_permissions rp ON rp.role_id = r.id WHERE r.id = ANY ($1::bigint[]) GROUP BY r.id",
            [$roles],
            as: Row::of(...),
        );
        foreach ($rows as $row) {
            if ($row->bool('builtin') || array_diff($row->list('permissions', 'string'), $by->permissions) !== []) {
                throw new AccountRefused(Refusal::RoleTooStrong);
            }
        }
    }

    /**
     * Gives the user $roles; a role deleted meanwhile is left out.
     *
     * @param list<int> $roles
     */
    private function assign(Postgres $tx, int $id, array $roles): void
    {
        foreach (array_unique($roles) as $role) {
            $tx->execute('INSERT INTO auth_user_roles (user_id, role_id) SELECT $1, id FROM auth_roles WHERE id = $2 ON CONFLICT DO NOTHING', [$id, $role]);
        }
    }

    private function clearTwoFactor(Postgres $db, int $id): void
    {
        $db->execute("UPDATE auth_users SET totp_secret = NULL, totp_enabled_at = NULL, totp_last_step = NULL, recovery_codes = '{}' WHERE id = $1", [$id]);
    }

    private static function hash(string $password): string
    {
        return password_hash($password, self::ALGORITHM);
    }

    private static function dummy(): string
    {
        return self::$dummyHash ??= self::hash(random_bytes(16));
    }

    /** Letters and digits only, any case: "K3X9P-2mfa7" and "k3x9p2mfa7" are the same code */
    private static function recoveryHash(string $code): string
    {
        return hash('sha256', strtolower(preg_replace('/[^A-Za-z0-9]/', '', $code) ?? ''));
    }
}
