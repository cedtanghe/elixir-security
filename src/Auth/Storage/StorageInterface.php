<?php

namespace Elixir\Security\Auth\Storage;

use Elixir\Security\Auth\Identity;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
interface StorageInterface
{
    /**
     * @param string $domain
     *
     * @return bool
     */
    public function hasIdentity($domain);

    /**
     * @param string $domain
     * @param mixed  $default
     *
     * @return mixed
     */
    public function getIdentity($domain, $default = null);

    /**
     * @param string   $domain
     * @param Identity $identity
     */
    public function addIdentity($domain, Identity $identity);

    /**
     * @param string $domain
     */
    public function clearIdentity($domain);

    /**
     * @return array
     */
    public function allIdentities();

    public function clearIdentities();
}
