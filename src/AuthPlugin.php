<?php

namespace Io\Auth;

use Io\Container;
use Io\PermissionProvider;
use Io\Plugin\PluginBase;

/**
 * Register with `$app->plugin(new AuthPlugin())`. The services need a `Data\Postgres` in the container and the tables
 * of Schema::steps() in the app's migrations; SessionMiddleware signs requests in.
 */
final class AuthPlugin extends PluginBase
{
    public function name(): string
    {
        return 'auth';
    }

    /** #[Permissions(...)] asks the roles; an app that sets PermissionOptions::$provider itself wins. */
    public function boot(Container $container): void
    {
        $container->bind(PermissionProvider::class, $container->get(RolePermissions::class));
    }
}
