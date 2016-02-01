<?php

namespace Elixir\Security\Auth\Storage;

use Elixir\Security\Auth\Identity;
use Elixir\Security\Auth\Storage\StorageInterface;
use Elixir\Security\Auth\Storage\StorageTrait;
use Elixir\Session\Session;
use Elixir\Session\SessionInterface;
use Elixir\STDLib\ArrayUtils;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Session implements StorageInterface 
{
    use StorageTrait;
    
    /**
     * @var string
     */
    const STORAGE_KEY = '___AUTH_STORAGE___';

    /**
     * @var SessionInterface|\ArrayAccess|array
     */
    protected $session;

    /**
     * @param SessionInterface|\ArrayAccess|array $session
     */
    public function __construct($session = null) 
    {
        $this->session = $session ?: Session::instance();
    }
    
    /**
     * {@inheritdoc}
     */
    public function hasIdentity($domain)
    {
        return ArrayUtils::has([self::STORAGE_KEY, $domain], $this->session);
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentity($domain, $default = null)
    {
        $identity = ArrayUtils::get([self::STORAGE_KEY, $domain], $this->session, $default);
        
        if ($identity instanceof Identity)
        {
            $this->observe($identity);
        }
        
        return $identity;
    }

    /**
     * {@inheritdoc}
     */
    public function addIdentity($domain, Identity $identity)
    {
        $identity->setDomain($domain);
        ArrayUtils::set([self::STORAGE_KEY, $domain], $identity, $this->session);
        
        $this->observe($identity);
    }

    /**
     * {@inheritdoc}
     */
    public function clearIdentity($domain)
    {
        $identity = $this->getIdentity($domain);
        
        if ($identity)
        {
            $identity->setDomain(null);
            ArrayUtils::remove([self::STORAGE_KEY, $domain], $this->session);
            
            $this->unObserve($identity);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function clearIdentities()
    {
        $identities = ArrayUtils::get(self::STORAGE_KEY, $this->session, []);
        
        foreach ($identities as $identity)
        {
            $identity->setDomain(null);
            $this->unObserve($identity);
        }
        
        ArrayUtils::remove(self::STORAGE_KEY, $this->session);
    }
}
