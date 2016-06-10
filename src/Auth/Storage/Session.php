<?php

namespace Elixir\Security\Auth\Storage;

use Elixir\Security\Auth\Identity;
use Elixir\Security\Auth\Storage\StorageInterface;
use Elixir\Security\Auth\Storage\StorageTrait;
use Elixir\Session\Session;
use Elixir\Session\SessionInterface;
use function Elixir\STDLib\array_get;
use function Elixir\STDLib\array_has;
use function Elixir\STDLib\array_remove;
use function Elixir\STDLib\array_set;

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
        return array_has([self::STORAGE_KEY, $domain], $this->session);
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentity($domain, $default = null)
    {
        $identity = array_get([self::STORAGE_KEY, $domain], $this->session, $default);
        
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
        array_set([self::STORAGE_KEY, $domain], $identity, $this->session);
        
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
            array_remove([self::STORAGE_KEY, $domain], $this->session);
            
            $this->unObserve($identity);
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function allIdentities()
    {
        $identities = array_get(self::STORAGE_KEY, $this->session, []);
        
        foreach ($identities as $identity)
        {
            $this->observe($identity);
        }
        
        return $identities;
    }
    
    /**
     * {@inheritdoc}
     */
    public function clearIdentities()
    {
        $identities = array_get(self::STORAGE_KEY, $this->session, []);
        
        foreach ($identities as $identity)
        {
            $identity->setDomain(null);
            $this->unObserve($identity);
        }
        
        array_remove(self::STORAGE_KEY, $this->session);
    }
}
