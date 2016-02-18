<?php

namespace Elixir\Security\Firewall;

use Elixir\Security\Firewall\AccessControlInterface;
use Elixir\STDLib\ArrayUtils;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
abstract class AccessControlAbstract implements AccessControlInterface, \ArrayAccess
{
    /**
     * @var array
     */
    protected $options = [];
    
    /**
     * @var string
     */
    protected $pattern;
    
    /**
     * @param string $pattern
     * @param array $options
     */
    public function __construct($pattern, array $options = [])
    {
        $this->pattern = $pattern;
        $this->mergeOptions($options);
    }
    
    /**
     * {@inheritdoc}
     */
    public function getPattern()
    {
        return $this->pattern;
    }

    /**
     * @param mixed $option
     * @return boolean
     */
    public function hasOption($option) 
    {
        return ArrayUtils::has($option, $this->options);
    }

    /**
     * @param mixed $option
     * @param mixed $default
     * @return mixed
     */
    public function getOption($option, $default = null)
    {
        return ArrayUtils::get($option, $this->options, $default);
    }
    
    /**
     * @param mixed $option
     * @param mixed $value
     */
    public function addOption($option, $value) 
    {
        ArrayUtils::set($option, $value, $this->options);
    }
    
    /**
     * @param mixed $option
     */
    public function removeOption($option) 
    {
        ArrayUtils::remove($option, $this->options);
    }

    /**
     * {@inheritdoc}
     */
    public function allOptions()
    {
        return $this->options;
    }

    /**
     * @param array $options
     */
    public function replaceOptions(array $options)
    {
        $this->options = [];

        foreach ($options as $key => $value)
        {
            $this->addOption($key, $value);
        }
    }
    
    /**
     * @param AccessControlInterface|array $options
     */
    public function mergeOptions($options)
    {
        if ($options instanceof self) 
        {
            $options = $options->allOptions();
        }

        $this->options = array_merge($this->options, $options);
    }

    /**
     * @ignore
     */
    public function offsetExists($key)
    {
        return $this->hasOption($key);
    }

    /**
     * @ignore
     */
    public function offsetSet($key, $value) 
    {
        $this->addOption($key, $value);
    }

    /**
     * @ignore
     */
    public function offsetGet($key) 
    {
        return $this->getOption($key);
    }

    /**
     * @ignore
     */
    public function offsetUnset($key)
    {
        $this->removeOption($key);
    }
    
    /**
     * @ignore
     */
    public function __debugInfo()
    {
        return [
            'options' => $this->options,
            'pattern' => $this->pattern
        ];
    }
}
