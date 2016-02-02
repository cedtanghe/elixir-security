<?php

namespace Elixir\Security\Firewall\RBAC;

use Elixir\Security\Firewall\AccessControlAbstract;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class AccessControl extends AccessControlAbstract
{
    /**
     * {@inheritdoc}
     */
    protected $options = [
        'roles' => [],
        'permissions' => [],
        'assert' => null,
        'domains' => []
    ];
}
