<?php

namespace Elixir\Security\Firewall;

use Elixir\Dispatcher\Event;
use Elixir\Security\Firewall\AccessControlInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class FirewallEvent extends Event
{
    /**
     * @var string
     */
    const ANALYSE = 'pre_analyse';

    /**
     * @var string
     */
    const RESOURCE_MATCHED = 'resource_matched';

    /**
     * @var string
     */
    const ACCESS_GRANTED = 'access_granted';

    /**
     * @var string
     */
    const ACCESS_FORBIDDEN = 'access_forbidden';

    /**
     * @var string
     */
    const IDENTITY_NOT_FOUND = 'identity_not_found';

    /**
     * @var string
     */
    const NO_ACCESS_CONTROLS_FOUND = 'no_access_controls_found';

    /**
     * @var string
     */
    protected $resource;

    /**
     * @var AccessControlInterface
     */
    protected $accessControl;

    /**
     * {@inheritdoc}
     * @param array $params
     */
    public function __construct($pType, array $params = [])
    {
        parent::__construct($pType);
        
        $params += [
            'resource' => null,
            'access_control' => null
        ];
        
        $this->resource = $params['resource'];
        $this->accessControl = $params['access_control'];
    }
    
    /**
     * @return string
     */
    public function getResource()
    {
        return $this->resource;
    }

    /**
     * @return AccessControlInterface
     */
    public function getAccessControl()
    {
        return $this->accessControl;
    }
}
