<?php

namespace Elixir\Security\RBAC;

use Elixir\Security\RBAC\RBACInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Role 
{
    /**
     * @var string
     */
    const ALL_PERMISSIONS_GRANTED = 'all_permissions_granted';

    /**
     * @var string|integer
     */
    protected $name;

    /**
     * @var RBACInterface
     */
    protected $RBAC;

    /**
     * @var array
     */
    protected $permissions = [];

    /**
     * @var array
     */
    protected $children = [];

    /**
     * @param string|integer $name
     * @param array $permisions
     */
    public function __construct($name, array $permisions = [])
    {
        $this->name = $name;
        $this->setPermissions($permisions);
    }

    /**
     * @return string|integer
     */
    public function getName() 
    {
        return $this->name;
    }

    /**
     * @internal
     * @param RBACInterface $RBAC
     */
    public function setRBAC(RBACInterface $RBAC)
    {
        $this->RBAC = $RBAC;
    }

    /**
     * @return RBACInterface
     */
    public function getRBAC() 
    {
        return $this->RBAC;
    }

    /**
     * @param string|integer|self $role
     * @return boolean
     */
    public function hasChild($role) 
    {
        if ($role instanceof self)
        {
            $role = $role->getName();
        }
        
        return array_key_exists($role, $this->children);
    }

    /**
     * @param string|integer|self $role
     */
    public function addChild($role) 
    {
        if (!$role instanceof self)
        {
            $role = new self($role);
        }
        
        $this->children[$role->getName()] = $role;
    }

    /**
     * @param string|integer|self $role
     */
    public function removeChild($role)
    {
        if ($role instanceof self)
        {
            $role = $role->getName();
        }
        
        unset($this->children[$role]);
    }

    /**
     * @param string|integer $permission
     * @return boolean
     */
    public function hasPermission($permission)
    {
        foreach ([$permission, self::ALL_PERMISSIONS_GRANTED] as $perm)
        {
            if (array_key_exists($perm, $this->permissions))
            {
                if (true !== $this->permissions[$perm]) 
                {
                    if (!call_user_func_array($this->permissions[$perm], [$this->RBAC]))
                    {
                        continue;
                    }
                }

                return true;
            }
        }

        foreach ($this->children as $child) 
        {
            if ($child->hasPermission($permission)) 
            {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string|integer $permission
     * @param callable $assert
     */
    public function addPermission($permission, callable $assert = null) 
    {
        $this->permissions[$permission] = $assert ?: true;
    }

    /**
     * @param string|integer $permission
     */
    public function removePermission($permission) 
    {
        unset($this->permissions[$permission]);
    }

    /**
     * @return array
     */
    public function getPermissions() 
    {
        return $this->permissions;
    }

    /**
     * @param array $permissions
     */
    public function setPermissions(array $permissions) 
    {
        $this->permissions = [];

        foreach ($permissions as $config)
        {
            if (is_array($config))
            {
                $this->addPermission($config['permission'], isset($config['assert']) ? $config['assert'] : null);
            } 
            else
            {
                $this->addPermission($config);
            }
        }
    }
}
