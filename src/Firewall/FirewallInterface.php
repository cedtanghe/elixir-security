<?php

namespace Elixir\Security\Firewall;

use Elixir\Dispatcher\DispatcherInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface FirewallInterface extends DispatcherInterface 
{
    /**
     * @param boolean $withInfos
     * @return array
     */
    public function allAccessControls($withInfos = false);

    /**
     * @param string $resource
     * @return boolean
     */
    public function analyze($resource);
}
