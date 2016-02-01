<?php

namespace Elixir\Security\Auth;

use Elixir\Security\Auth\Result;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface AuthenticatorInterface
{
    /**
     * @return Result
     */
    public function authenticate();
}
