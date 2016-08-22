<?php

namespace Elixir\Security\RBAC;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface RBACInterface
{
    /**
     * @param string|int|Role $role
     *
     * @return bool
     */
    public function hasRole($role);

    /**
     * @return array
     */
    public function getRoles();

    /**
     * @param string|int       $role
     * @param string|int|array $permission
     * @param callable         $assert
     *
     * @return bool
     */
    public function isGranted($role = null, $permission = null, callable $assert = null);
}
