<?php

namespace Elixir\Security\Firewall\Behavior;

use Elixir\MVC\Exception\ForbiddenException;
use Elixir\Security\Firewall\Behavior\BehaviorInterface;
use Elixir\Security\Firewall\FirewallInterface;
use Elixir\STDLib\Facade\I18N;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class AccessForbidden implements BehaviorInterface
{
    /**
     * @var string 
     */
    protected $message;

    /**
     * @param string $message
     */
    public function __construct($message = null)
    {
        $this->message = $message ?: I18N::__('You do not have permission to access this resource.', ['context' => 'elixir']);
    }

    /**
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }
    
    /**
     * {@inheritdoc}
     * @throws ForbiddenException
     */
    public function __invoke(FirewallInterface $firewall)
    {
        throw new ForbiddenException($this->message);
    }
}
