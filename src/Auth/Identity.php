<?php

namespace Elixir\Security\Auth;

use Elixir\Dispatcher\DispatcherInterface;
use Elixir\Dispatcher\DispatcherTrait;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Identity implements DispatcherInterface, \ArrayAccess
{
    use DispatcherTrait;

    /**
     * @var mixed
     */
    protected $securityContext;

    /**
     * @var array|\ArrayAccess
     */
    protected $data;

    /**
     * @var string
     */
    protected $domain;

    /**
     * @param array|\ArrayAccess $data
     * @param mixed              $securityContext
     */
    public function __construct($data = [], $securityContext = null)
    {
        $this->data = $data;
        $this->securityContext = $securityContext;
    }

    /**
     * @param mixed $context
     */
    public function setSecurityContext($context)
    {
        $this->securityContext = $context;
    }

    /**
     * @return mixed
     */
    public function getSecurityContext()
    {
        return $this->securityContext;
    }

    /**
     * @param array $data
     */
    public function setData(array $data)
    {
        $this->data = $data;
    }

    /**
     * @return array|\ArrayAccess
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * @internal
     *
     * @param string $domain
     */
    public function setDomain($domain)
    {
        $this->domain = $domain;
    }

    /**
     * @internal
     *
     * @return string
     */
    public function getDomain()
    {
        return $this->domain;
    }

    public function update()
    {
        $this->dispatch(new AuthEvent(AuthEvent::IDENTITY_UPDATED));
    }

    /**
     * @internal
     */
    public function remove()
    {
        $this->dispatch(new AuthEvent(AuthEvent::IDENTITY_REMOVED));
    }

    /**
     * @ignore
     */
    public function offsetExists($key)
    {
        return isset($this->data[$key]);
    }

    /**
     * @ignore
     */
    public function offsetSet($key, $value)
    {
        $this->data[$key] = $value;
    }

    /**
     * @ignore
     */
    public function offsetGet($key)
    {
        return isset($this->data[$key]) ? $this->data[$key] : null;
    }

    /**
     * @ignore
     */
    public function offsetUnset($key)
    {
        unset($this->data[$key]);
    }

    /**
     * @ignore
     */
    public function __isset($key)
    {
        return $this->offsetExists($key);
    }

    /**
     * @ignore
     */
    public function __get($key)
    {
        return $this->offsetGet($key);
    }

    /**
     * @ignore
     */
    public function __set($key, $value)
    {
        $this->offsetSet($key, $value);
    }

    /**
     * @ignore
     */
    public function __unset($key)
    {
        $this->offsetUnset($key);
    }

    /**
     * @ignore
     */
    public function __debugInfo()
    {
        return [
            'data' => $this->data,
            'domain' => $this->domain,
            'security_context' => $this->securityContext ? get_class($this->securityContext) : null,
        ];
    }
}
