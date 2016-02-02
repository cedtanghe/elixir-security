<?php

namespace Elixir\Security\Firewall\Identity;

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
        'assert' => null,
        'domains' => []
    ];
}
