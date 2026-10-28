<?php

namespace Io\Auth;

/**
 * The permissions roles are built from. The app and every plugin add theirs with their label for the role editor:
 * `$app->get(PermissionCatalog::class)->add('pages.edit', 'Edit pages')`. A permission not in here can't be given.
 */
final class PermissionCatalog
{
    /** @var array<string, string> name => label */
    private array $permissions = [];

    public function add(string $name, string $label): self
    {
        $this->permissions[$name] = $label;

        return $this;
    }

    public function has(string $name): bool
    {
        return isset($this->permissions[$name]);
    }

    /** @return array<string, string> name => label, in the order they were added */
    public function all(): array
    {
        return $this->permissions;
    }
}
