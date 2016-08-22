<?php

namespace Elixir\Security\Auth;

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
