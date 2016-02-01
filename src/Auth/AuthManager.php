<?php

namespace Elixir\Security\Auth;

use Elixir\Dispatcher\Dispatcher;
use Elixir\Security\Auth\AuthenticatorInterface;
use Elixir\Security\Auth\Result;
use Elixir\Security\Auth\Storage\StorageInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class AuthManager extends Dispatcher 
{

    /**
     * @var string
     */
    const DEFAULT_IDENTITY = 'default';

    /**
     * @var StorageInterface 
     */
    protected $storage;

    /**
     * @param StorageInterface $storage
     */
    public function __construct(StorageInterface $storage) 
    {
        $this->storage = $storage;
    }
    
    /**
     * @return StorageInterface 
     */
    public function getStorage() 
    {
        return $this->storage;
    }
    
    /**
     * @param AuthenticatorInterface $authenticator
     * @param string $domain
     * @return Result
     */
    public function authenticate(AuthenticatorInterface $authenticator, $domain = self::DEFAULT_IDENTITY)
    {
        $result = $authenticator->authenticate();
        
        if($result->isSuccess())
        {
            $this->addIdentity($domain, $result->getIdentity());
        }
        
        return $result;
    }
    
    /**
     * @ignore
     */
    public function __call($name, $arguments)
    {
        return call_user_func_array([$this->storage, $name], $arguments);
    }
}
