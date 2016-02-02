<?php

namespace Elixir\Security\RBAC;

use Elixir\Security\RBAC\Role;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface RBACInterface 
{
    /**
     * @param string|integer|Role $role
     * @return boolean
     */
    public function hasRole($role);

    /**
     * @return array
     */
    public function getRoles();

    /**
     * @param string|integer $role
     * @param string|integer|array $permission
     * @param callable $assert
     * @return boolean
     */
    public function isGranted($role = null, $permission = null, callable $assert = null);
}
