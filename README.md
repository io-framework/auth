# io/auth

Sign-in for Io sites on Postgres:

- users with Argon2id passwords
- database sessions in a cookie
- TOTP with recovery codes
- one-time tokens (password links, pending logins, PINs)
- a login throttle
- roles built from the permissions the app declares, with a built-in Admin role

Pages, forms and mails stay with the app: io/auth hands out the token, the app sends the link.

## Setup

```php
use Io\Auth\{AuthOptions, AuthPlugin, PermissionCatalog, Schema, SessionMiddleware};

$app->plugin(new AuthPlugin());
$app->configure(function (AuthOptions $auth) {
    $auth->cookie = '__Host-session'; // the default
    $auth->idle = 12 * 3600;           // seconds after the last request
    $auth->lifetime = 30 * 86400;      // seconds at most
    $auth->recheck = 300;              // seconds a WebSocket keeps its user before it reads the session again
    $auth->remember = false;           // true: the cookie outlives the browser
    $auth->displayName = true;         // false: users have only a handle
});
$app->getContainer()->set(Data\Postgres::connect($url));
$app->use($app->get(SessionMiddleware::class));

$app->get(PermissionCatalog::class)
    ->add('pages.edit', 'Edit pages')
    ->add('users.manage', 'Manage users');
```

The tables come as steps for `Data\Migrations`, before the app's own, so its tables can refer to `auth_users`:

```php
new Data\Migrations($db)->apply([...Schema::steps(), '001_posts' => 'CREATE TABLE posts (...)']);
```

An app may add columns of its own to `auth_users` in its migrations.

## Handles and names

Every user has a handle for addresses like `/u/kakashi`: 3 to 32 of `a-z`, `0-9`, `_` and `-`, kept in lower case.
Next to it a display name, unless `AuthOptions::$displayName` is off: then the app's forms ask for none and the
handle stands in for it. Both are unique; two display names that differ only in case count as the same, and a name
that hides a look-alike letter from another script ("Kakashi" with a Cyrillic а) is refused.

```php
$id = $users->create('kakashi@example.test', 'kakashi', 'Kakashi Hatake', $password);
$users->update($id, $email, $handle, $name);   // AccountRefused: HandleTaken, NameTaken, InvalidHandle, InvalidName
$users->byHandle('kakashi');
$users->handleTaken($handle, except: $id);    // for a form's message before it submits
Users::handle($input);                         // the handle as kept, null when invalid; Users::name() likewise
```

## Signing in

```php
$id = $users->authenticate($email, $password);       // null for a wrong password, an unknown or disabled user
if ($id !== null && $users->twoFactor($id)['enabled']) {
    // wait for the code: a token for the pending login, bound to a cookie of the browser
    $ticket = $tokens->issue('login', $id, 300, bind: $browserSecret);
}
$users->verifySecondFactor($id, $code);              // a TOTP code (each step once) or a recovery code (once)
$sessions->start($id, $req, $res);                   // only once the login is complete
```

`SessionMiddleware` signs every request in. `Viewer::current()` returns the `Principal` (id, handle, name, email, roles,
admin, permissions, `can()`), and `$req->principal` holds its claims. `#[Authenticated]`, `#[Role('Editors')]` and
`#[Permissions('pages.edit')]` check it; `AuthPlugin` binds the `PermissionProvider` that asks the roles.

A WebSocket (io/live) keeps the user it opened with. The claims carry `sid`, the session, and `exp`, at most
`$recheck` seconds ahead: then the connection opens again and the session is read anew. Ending sessions early
(`end()`, `endOthers()`, `setDisabled()`, `resetTwoFactor()`) announces them through Io's `SignOuts`, and the
open connections of those sessions close at once.

`LoginThrottle::attempt($req->ip, $email)` counts an attempt before it is checked: 5 per account and address,
20 per address and 50 per account in 15 minutes. It lives in the worker's memory.

## Roles

`Roles` creates, renames and deletes roles and sets their permissions and whether they ask for a second factor.
`Users::setRoles()`, `setDisabled()`, `resetTwoFactor()` and `create(..., roles:, by:)` follow these rules and throw
`AccountRefused` with a `Refusal` otherwise:

- the Admin role has every permission, always asks for a second factor and can't be changed or deleted
- nobody changes their own account, and only an admin changes an admin
- someone who isn't an admin hands out (or takes away) only roles that allow no more than they may do themselves,
  and changes only the permissions of a role that they hold
- the site keeps at least one active admin

## License

MIT or Apache-2.0, at your option.
