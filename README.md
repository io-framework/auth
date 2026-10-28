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
    $auth->remember = false;           // true: the cookie outlives the browser
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

`SessionMiddleware` signs every request in. `Viewer::current()` returns the `Principal` (id, name, email, roles,
admin, permissions, `can()`), and `$req->principal` holds its claims. `#[Authenticated]`, `#[Role('Editors')]` and
`#[Permissions('pages.edit')]` check it; `AuthPlugin` binds the `PermissionProvider` that asks the roles.

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
