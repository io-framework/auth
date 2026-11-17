<?php
// tenma tests/Fixtures/flow.php: every service against the database in DATABASE_URL; prints "ok", or why not.

use Data\{Migrations, Postgres};
use Io\App;
use Io\Auth\{AccountRefused, AuthOptions, PermissionCatalog, Principal, Refusal, Roles, Schema, Sealed, Sessions, Tokens, Totp, Users};
use Io\Http\{Request, Response};
use Threading\Task;

require __DIR__ . '/../../vendor/autoload.php';

function check(bool $condition, string $what): void
{
    if (!$condition) {
        throw new RuntimeException("failed: $what");
    }
}

/**
 * What js/seal.js does in the browser, in PHP: an ephemeral key, ECDH, HKDF, AES-GCM.
 *
 * @param array{key: string, challenge: string} $handshake
 * @return array{challenge: string, key: string, iv: string, data: string}
 */
function seal(array $handshake, string $text): array
{
    $b64 = fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    $un = fn (string $text): string => (string) base64_decode(strtr($text, '-_', '+/'));
    $pem = fn (string $point): string => "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode((string) hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . $point), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $own = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    check($own !== false, 'ephemeral key');
    $details = openssl_pkey_get_details($own);
    $point = "\x04" . str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT) . str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
    $salt = $un($handshake['challenge']);
    $server = openssl_pkey_get_public($pem($un($handshake["key"])));
    check($server !== false, "server key");
    $shared = openssl_pkey_derive($server, $own);
    $aes = hash_hkdf('sha256', (string) $shared, 32, 'io-auth-seal', $salt);
    $iv = random_bytes(12);
    $data = (string) openssl_encrypt($text, 'aes-256-gcm', $aes, OPENSSL_RAW_DATA, $iv, $tag, $salt);

    return ['challenge' => $handshake['challenge'], 'key' => $b64($point), 'iv' => $b64($iv), 'data' => $b64($data . $tag)];
}

function refused(Refusal $reason, callable $work): void
{
    try {
        $work();
    } catch (AccountRefused $e) {
        check($e->reason === $reason, "refused as {$reason->value}, not {$e->reason->value}");

        return;
    }
    throw new RuntimeException("not refused: {$reason->value}");
}

Task::run(function (): void {
    try {
        $app = App::create();
        $db = Postgres::connect((string) getenv('DATABASE_URL'));
        $app->getContainer()->set($db);
        $app->configure(fn (AuthOptions $auth) => $auth->cookie = 'test_session');
        // Users from before handles get one made from their name
        $steps = Schema::steps();
        new Migrations($db)->apply(['auth_001_accounts' => $steps['auth_001_accounts']]);
        $db->execute("INSERT INTO auth_users (email, name) VALUES ('old1@example.test', 'Zoë Kim'), ('old2@example.test', 'ZOË KIM'), ('old3@example.test', 'Al')");
        new Migrations($db)->apply($steps);
        $old = $db->query('SELECT handle, name FROM auth_users ORDER BY id', as: fn (array $row): string => $row['handle'] . '|' . $row['name']);
        check($old === ['zoe_kim|Zoë Kim', 'zoe_kim_2|ZOË KIM (2)', 'al_3|Al'], 'handles for old users: ' . implode(', ', $old));
        $db->execute('DELETE FROM auth_users');
        $app->get(PermissionCatalog::class)->add('pages.edit', 'Edit pages')->add('users.manage', 'Manage users');
        $users = $app->get(Users::class);
        $roles = $app->get(Roles::class);
        $sessions = $app->get(Sessions::class);
        $tokens = $app->get(Tokens::class);

        // The first admin, once
        $ada = $users->createFirstAdmin('ada@example.test', 'Ada', 'correct horse battery', 'Ada Lovelace');
        check($ada !== null, 'first admin');
        check($users->createFirstAdmin('bob@example.test', 'bob', 'x', 'Bob') === null, 'only one first admin');
        check($users->authenticate('ADA@example.test ', 'correct horse battery') === $ada, 'sign in, any case');
        check($users->authenticate('ada@example.test', 'wrong') === null, 'wrong password');
        check($users->authenticate('nobody@example.test', 'x') === null, 'unknown email');
        refused(Refusal::EmailTaken, fn () => $users->create('Ada@example.test', 'ada2', 'Ada 2'));

        // Handle and display name are unique; the name in any case, and without look-alike letters
        check($users->byHandle(' ADA')?->id === $ada && $users->find($ada)?->name === 'Ada Lovelace', 'by handle');
        refused(Refusal::HandleTaken, fn () => $users->create('ada2@example.test', 'ada', 'Ada 2'));
        refused(Refusal::NameTaken, fn () => $users->create('ada2@example.test', 'ada2', ' ADA  lovelace'));
        refused(Refusal::InvalidName, fn () => $users->create('ada2@example.test', 'ada2', "Ada Lоvelace"));
        refused(Refusal::InvalidName, fn () => $users->create('ada2@example.test', 'ada2', "Ada\u{200B}"));
        refused(Refusal::InvalidHandle, fn () => $users->create('ada2@example.test', 'ad', 'Ada 2'));
        refused(Refusal::InvalidHandle, fn () => $users->create('ada2@example.test', 'ada/2', 'Ada 2'));
        check($users->nameTaken('ada lovelace') && !$users->nameTaken('ada lovelace', $ada) && $users->handleTaken('ADA'), 'taken');

        // A session signs the request in, with the Admin role
        $res = new Response();
        $sessions->start($ada, Request::fromParts('POST', '/login', ['User-Agent' => 'test']), $res);
        preg_match('/^test_session=([0-9a-f]{64})/', $res->getCookies()[0] ?? '', $cookie);
        check(isset($cookie[1]), 'session cookie');
        $req = Request::fromParts('GET', '/', cookies: ['test_session' => $cookie[1]]);
        $principal = $sessions->signIn($req);
        check($principal?->admin === true && $principal->can('anything'), 'admin may do everything');
        check($principal->handle === 'ada' && $principal->name === 'Ada Lovelace', 'principal names');
        check(($req->principal['roles'] ?? null) === ['Admin'] && $req->principalFromCookie, 'request signed in');
        // A WebSocket asks again after AuthOptions::$recheck, and hears when the session ends before
        $exp = $req->principal['exp'] ?? 0;
        check($req->principal['sid'] === (string) $principal->session && $exp > time() && $exp <= time() + 300, 'sid and exp');

        // A role an editor can't exceed
        $editors = $roles->create('Editors');
        refused(Refusal::RoleTaken, fn () => $roles->create('editors'));
        $roles->update($principal, $editors, 'Editors', ['pages.edit', 'users.manage', 'nonsense'], false);
        check($roles->find($editors)?->permissions === ['pages.edit', 'users.manage'], 'unknown permissions left out');
        $admin = $roles->all()[0];
        refused(Refusal::BuiltinRole, fn () => $roles->update($principal, $admin->id, 'Chief', [], false));
        refused(Refusal::BuiltinRole, fn () => $roles->delete($admin->id));

        $ed = $users->create('ed@example.test', 'edgar', 'Ed', roles: [$editors], by: $principal);
        check($users->find($ed)?->hasPassword === false, 'invited without a password');
        $link = $tokens->issue('password', $ed, 3600);
        check($tokens->user('password', $link) === $ed, 'link is valid');
        check($tokens->redeem('password', $link) === $ed && $tokens->redeem('password', $link) === null, 'link works once');
        $users->setPassword($ed, 'another long password');
        check($users->authenticate('ed@example.test', 'another long password') === $ed, 'ed signs in');

        // Ed may not hand out the Admin role or change Ada
        $edSession = new Principal($ed, 0, 'edgar', 'Ed', 'ed@example.test', ['Editors'], false, ['pages.edit', 'users.manage']);
        refused(Refusal::RoleTooStrong, fn () => $users->create('fay@example.test', 'fay', 'Fay', roles: [$admin->id], by: $edSession));
        refused(Refusal::AdminOnly, fn () => $users->setDisabled($edSession, $ada, true));
        refused(Refusal::OwnAccount, fn () => $users->setRoles($principal, $ada, []));
        // Someone who may only edit pages leaves the other permissions of a role as they are
        $writer = new Principal($ed, 0, 'edgar', 'Ed', 'ed@example.test', ['Writers'], false, ['pages.edit']);
        $roles->update($writer, $editors, 'Editors', [], true);
        check($roles->find($editors)?->permissions === ['users.manage'], 'only own permissions taken away');
        $roles->update($writer, $editors, 'Editors', ['pages.edit'], true);
        check($roles->find($editors)?->permissions === ['pages.edit', 'users.manage'], 'own permissions only');
        check($users->twoFactor($ed) === ['enabled' => false, 'required' => true], 'role asks for 2FA');

        // The second factor, each step once, and a recovery code once
        $secret = Totp::secret();
        $codes = Users::recoveryCodes();
        check(!$users->enableTwoFactor($ed, $secret, '000000', $codes), 'wrong code');
        $step = intdiv(time(), 30);
        check($users->enableTwoFactor($ed, $secret, Totp::code($secret, $step), $codes), '2FA on');
        check(!$users->verifySecondFactor($ed, Totp::code($secret, $step)), 'a step works once');
        check($users->verifySecondFactor($ed, Totp::code($secret, $step + 1)), 'the next step works');
        check($users->verifySecondFactor($ed, strtoupper($codes[0])), 'recovery code, any case');
        check(!$users->verifySecondFactor($ed, $codes[0]), 'a recovery code works once');

        // A bound token, a PIN
        $ticket = $tokens->issue('login', $ed, 60, bind: 'browser-a');
        check($tokens->redeem('login', $ticket, 'browser-b') === null, 'other browser');
        check($tokens->redeem('login', $ticket, 'browser-a') === $ed, 'own browser');
        $pin = $tokens->pin('discord', $ed, 60);
        check(preg_match('/^\d{4}-\d{4}$/', $pin) === 1 && $tokens->redeem('discord', str_replace('-', '', $pin)) === $ed, 'PIN');

        // Disabled: no sign-in, no session, and the last admin stays
        $users->setDisabled($principal, $ed, true);
        check($users->authenticate('ed@example.test', 'another long password') === null, 'disabled');
        $users->setRoles($principal, $ed, [$admin->id]);
        refused(Refusal::LastAdmin, fn () => $users->setDisabled(new Principal($ed, 0, 'edgar', 'Ed', '', ['Admin'], true, []), $ada, true));

        // Without display names, the handle stands in
        $app->get(AuthOptions::class)->displayName = false;
        $kim = $users->create('kim@example.test', 'kim', 'Not kept');
        check($users->find($kim)?->name === 'kim' && !$users->nameTaken('Not kept'), 'no display name');

        // A session as a bare token, for an API that signs in for other apps
        $token = $sessions->issue($kim, 'game server');
        check($sessions->byToken($token)?->id === $kim && $sessions->byToken('nonsense') === null, 'token session');
        $sessions->endToken($token);
        check($sessions->byToken($token) === null, 'token session ended');

        // An account someone set up with a known password: new password, then a second factor
        $users->setPassword($kim, 'handed over');
        $users->requireSetup($kim);
        check($users->pending($kim)->passwordChange && $users->pending($kim)->twoFactorSetup, 'both pending');
        $users->setPassword($kim, 'my own now');
        check(!$users->pending($kim)->passwordChange && $users->pending($kim)->twoFactorSetup, 'password done');
        $kimSecret = Totp::secret();
        $users->enableTwoFactor($kim, $kimSecret, Totp::code($kimSecret, intdiv(time(), 30)), Users::recoveryCodes());
        check($users->pending($kim)->none(), 'nothing pending');

        // Sealed: the app in between passes on what it can't read, once
        $app->get(AuthOptions::class)->sealKeyFile = sys_get_temp_dir() . '/io-auth-seal-test.pem';
        @unlink(sys_get_temp_dir() . '/io-auth-seal-test.pem');
        $sealed = $app->get(Sealed::class);
        $envelope = seal($sealed->challenge(), '{"password":"secret"}');
        check($sealed->open(...$envelope) === '{"password":"secret"}', 'sealed opens');
        check($sealed->open(...$envelope) === null, 'a challenge works once');
        $tampered = seal($sealed->challenge(), 'x');
        $tampered['data'] = strrev($tampered['data']);
        check($sealed->open(...$tampered) === null, 'tampered data');
        check(substr(sprintf('%o', fileperms(sys_get_temp_dir() . '/io-auth-seal-test.pem')), -3) === '600', 'key file private');

        // SignOuts' channel, which Io keeps private
        $signedOut = [];
        $listening = new \Messaging\Channel('io-sign-outs')->subscribe(function (string $ids) use (&$signedOut): void {
            $signedOut[] = $ids;
        });
        \Threading\Task::delay(0.05);
        $sessions->end($req);
        check($sessions->find($req) === null, 'signed out');
        \Threading\Task::delay(0.05);
        $listening->cancel();
        check($signedOut === [(string) $principal->session], 'sign-out announced');
        echo "ok\n";
    } catch (Throwable $e) {
        echo $e::class . ': ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . "\n";
    }
});
