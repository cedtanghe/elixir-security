<?php

namespace Elixir\Security\Firewall\Behavior;

use Elixir\Security\Firewall\FirewallInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface BehaviorInterface
{
    /**
     * @param FirewallInterface $firewall
     */
    public function __invoke(FirewallInterface $firewall);
}
