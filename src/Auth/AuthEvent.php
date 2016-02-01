<?php

namespace Elixir\Security\Auth;

use Elixir\Dispatcher\Event;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class AuthEvent extends Event 
{
    /**
     * @var string
     */
    const IDENTITY_UPDATED = 'identity_updated';
    
    /**
     * @var string
     */
    const IDENTITY_REMOVED = 'identity_removed';
}
