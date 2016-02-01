<?php

namespace Elixir\Security\Auth\Storage;

use Elixir\Security\Auth\AuthEvent;
use Elixir\Security\Auth\Identity;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
trait StorageTrait 
{
    /**
     * @var array
     */
    protected $identities = []; 
    
    /**
     * @param Identity $identity
     */
    protected function observe(Identity $identity)
    {
        if (!in_array($identity, $this->identities, true))
        {
            $identity->addListener(AuthEvent::IDENTITY_UPDATED, [$this, 'onIdentityUpdated']);
            $identity->addListener(AuthEvent::IDENTITY_REMOVED, [$this, 'onIdentityRemoved']);
            
            $this->identities[] = $identity;
        }
    }
    
    /**
     * @param Identity $identity
     */
    protected function unObserve(Identity $identity)
    {
        if ($pos = array_search($identity, $this->identities, true))
        {
            $identity->removeListener(AuthEvent::IDENTITY_UPDATED, [$this, 'onIdentityUpdated']);
            $identity->removeListener(AuthEvent::IDENTITY_REMOVED, [$this, 'onIdentityRemoved']);
            
            array_splice($this->identities, $pos, 1);
        }
    }
    
    /**
     * @internal
     */
    public function onIdentityUpdated(AuthEvent $event)
    {
        $this->addIdentity($event->getTarget()->getDomain(), $event->getTarget());
    }

    /**
     * @internal
     */
    public function onIdentityRemoved(AuthEvent $event) 
    {
        $this->clearIdentity($event->getTarget()->getDomain());
    }
}
