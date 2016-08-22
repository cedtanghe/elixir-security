<?php

namespace Elixir\Security\Firewall;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface AccessControlInterface
{
    /**
     * @var string
     */
    const GLOBAL_CONFIG = 'global';

    /**
     * @var string
     */
    const OPTIONS = 'options';

    /**
     * @var string
     */
    const PRIORITY = 'priority';

    /**
     * @return string
     */
    public function getPattern();

    /**
     * @return array
     */
    public function allOptions();
}
