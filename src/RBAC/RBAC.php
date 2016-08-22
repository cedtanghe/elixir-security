<?php

namespace Elixir\Security\RBAC;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class RBAC implements RBACInterface
{
    /**
     * @var array
     */
    protected $roles = [];

    /**
     * @param array $roles
     */
    public function __construct(array $roles = [])
    {
        $this->setRoles($roles);
    }

    /**
     * {@inheritdoc}
     */
    public function hasRole($role)
    {
        if ($role instanceof Role) {
            $role = $role->getName();
        }

        foreach ($this->roles as $role) {
            if ($role->getName() == $role) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string|int|Role $role
     * @param string|array    $parents
     */
    public function addRole($role, $parents = [])
    {
        if (!$role instanceof Role) {
            $role = new Role($role);
        }

        $role->setRBAC($this);
        $this->roles[] = $role;

        foreach ((array) $parents as $parent) {
            if (!$parent instanceof Role) {
                $parent = $this->getRole(
                    $parent,
                    function () use ($parent) {
                        return new Role($parent);
                    }
                );
            }

            $parent->addChild($role);
            $this->addRole($parent);
        }
    }

    /**
     * @param string|int|Role $role
     *
     * @return bool
     */
    public function removeRole($role)
    {
        if ($role instanceof Role) {
            $role = $role->getName();
        }

        $i = count($this->roles);

        while ($i--) {
            $r = $this->roles[$i];

            if ($r->getName() == $role) {
                array_splice($this->roles, $i, 1);
            }
        }

        foreach ($this->roles as $r) {
            $r->removeChild($role);
        }
    }

    /**
     * @param string|int|Role $role
     * @param mixed           $default
     *
     * @return Role
     */
    public function getRole($role, $default = null)
    {
        if ($role instanceof Role) {
            return $role;
        }

        foreach ($this->roles as $r) {
            if ($r->getName() == $role) {
                return $r;
            }
        }

        return is_callable($default) ? call_user_func($default) : $default;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * @param array $data
     */
    public function setRoles(array $data)
    {
        $this->roles = [];

        foreach ($data as $config) {
            $role = $config;
            $permissions = [];
            $parents = [];

            if (is_array($config)) {
                $role = $config['role'];

                if (isset($config['permissions'])) {
                    $permissions = $config['permissions'];
                }

                if (isset($config['parents'])) {
                    $parents = $config['parents'];
                }
            }

            $role = $role instanceof Role ? $role : new Role($role);

            if (count($permissions) > 0) {
                $role->setPermissions($permissions);
            }

            $this->addRole($role, $parents);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isGranted($role = null, $permission = null, callable $assert = null)
    {
        $permissionExists = function ($permission, array $roles) {
            if (null === $permission) {
                return true;
            }

            foreach ($roles as $r) {
                if ($r->hasPermission($permission)) {
                    return true;
                }
            }

            return false;
        };

        if ($role && $this->hasRole($role)) {
            $hasRole = true;
            $hasPermission = $permissionExists($permission, [$this->getRole($role)]);
        } else {
            $hasRole = null === $role;
            $hasPermission = $permissionExists($permission, $this->roles);
        }

        if (null !== $assert) {
            return true === call_user_func_array($assert, [['has_role' => $hasRole, 'has_permission' => $hasPermission, 'RBAC' => $this]]);
        }

        return $hasRole && $hasPermission;
    }
}
