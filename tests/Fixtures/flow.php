<?php
// tenma tests/Fixtures/flow.php: every service against the database in DATABASE_URL; prints "ok", or why not.

use Data\{Migrations, Postgres};
use Io\App;
use Io\Auth\{AccountRefused, AuthOptions, PermissionCatalog, Principal, Refusal, Roles, Schema, Sessions, Tokens, Totp, Users};
use Io\Http\{Request, Response};
use Threading\Task;

require __DIR__ . '/../../vendor/autoload.php';

function check(bool $condition, string $what): void
{
    if (!$condition) {
        throw new RuntimeException("failed: $what");
    }
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
        new Migrations($db)->apply(Schema::steps());
        $app->get(PermissionCatalog::class)->add('pages.edit', 'Edit pages')->add('users.manage', 'Manage users');
        $users = $app->get(Users::class);
        $roles = $app->get(Roles::class);
        $sessions = $app->get(Sessions::class);
        $tokens = $app->get(Tokens::class);

        // The first admin, once
        $ada = $users->createFirstAdmin('ada@example.test', 'Ada', 'correct horse battery');
        check($ada !== null, 'first admin');
        check($users->createFirstAdmin('bob@example.test', 'Bob', 'x') === null, 'only one first admin');
        check($users->authenticate('ADA@example.test ', 'correct horse battery') === $ada, 'sign in, any case');
        check($users->authenticate('ada@example.test', 'wrong') === null, 'wrong password');
        check($users->authenticate('nobody@example.test', 'x') === null, 'unknown email');
        refused(Refusal::EmailTaken, fn () => $users->create('Ada@example.test', 'Ada 2'));

        // A session signs the request in, with the Admin role
        $res = new Response();
        $sessions->start($ada, Request::fromParts('POST', '/login', ['User-Agent' => 'test']), $res);
        preg_match('/^test_session=([0-9a-f]{64})/', $res->getCookies()[0] ?? '', $cookie);
        check(isset($cookie[1]), 'session cookie');
        $req = Request::fromParts('GET', '/', cookies: ['test_session' => $cookie[1]]);
        $principal = $sessions->signIn($req);
        check($principal?->admin === true && $principal->can('anything'), 'admin may do everything');
        check(($req->principal['roles'] ?? null) === ['Admin'] && $req->principalFromCookie, 'request signed in');

        // A role an editor can't exceed
        $editors = $roles->create('Editors');
        refused(Refusal::RoleTaken, fn () => $roles->create('editors'));
        $roles->update($principal, $editors, 'Editors', ['pages.edit', 'users.manage', 'nonsense'], false);
        check($roles->find($editors)?->permissions === ['pages.edit', 'users.manage'], 'unknown permissions left out');
        $admin = $roles->all()[0];
        refused(Refusal::BuiltinRole, fn () => $roles->update($principal, $admin->id, 'Chief', [], false));
        refused(Refusal::BuiltinRole, fn () => $roles->delete($admin->id));

        $ed = $users->create('ed@example.test', 'Ed', roles: [$editors], by: $principal);
        check($users->find($ed)?->hasPassword === false, 'invited without a password');
        $link = $tokens->issue('password', $ed, 3600);
        check($tokens->user('password', $link) === $ed, 'link is valid');
        check($tokens->redeem('password', $link) === $ed && $tokens->redeem('password', $link) === null, 'link works once');
        $users->setPassword($ed, 'another long password');
        check($users->authenticate('ed@example.test', 'another long password') === $ed, 'ed signs in');

        // Ed may not hand out the Admin role or change Ada
        $edSession = new Principal($ed, 0, 'Ed', 'ed@example.test', ['Editors'], false, ['pages.edit', 'users.manage']);
        refused(Refusal::RoleTooStrong, fn () => $users->create('fay@example.test', 'Fay', roles: [$admin->id], by: $edSession));
        refused(Refusal::AdminOnly, fn () => $users->setDisabled($edSession, $ada, true));
        refused(Refusal::OwnAccount, fn () => $users->setRoles($principal, $ada, []));
        // Someone who may only edit pages leaves the other permissions of a role as they are
        $writer = new Principal($ed, 0, 'Ed', 'ed@example.test', ['Writers'], false, ['pages.edit']);
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
        refused(Refusal::LastAdmin, fn () => $users->setDisabled(new Principal($ed, 0, 'Ed', '', ['Admin'], true, []), $ada, true));

        $sessions->end($req);
        check($sessions->find($req) === null, 'signed out');
        echo "ok\n";
    } catch (Throwable $e) {
        echo $e::class . ': ' . $e->getMessage() . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . "\n";
    }
});
