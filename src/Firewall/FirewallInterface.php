<?php

namespace Elixir\Security\Firewall;

use Elixir\Dispatcher\DispatcherInterface;
use Elixir\Security\Firewall\Behavior\BehaviorInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface FirewallInterface extends DispatcherInterface
{
    /**
     * @param bool $withInfos
     *
     * @return array
     */
    public function allAccessControls($withInfos = false);

    /**
     * @param BehaviorInterface $behavior
     */
    public function setFailedBehavior(BehaviorInterface $behavior);

    /**
     * @param BehaviorInterface $behavior
     */
    public function setSucessBehavior(BehaviorInterface $behavior);

    /**
     * @param bool $authorize
     *
     * @return mixed
     */
    public function applyBehavior($authorize);

    /**
     * @param string $resource
     *
     * @return bool
     */
    public function analyze($resource);
}
