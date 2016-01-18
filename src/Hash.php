<?php

namespace Elixir\Security;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Hash
{
    /**
     * @var array
     */
    protected static $supportedAlgorithms;

    /**
     * @param string $algo
     * @param string $str
     * @param boolean $raw
     * @return string
     * @throws \InvalidArgumentException
     */
    public static function hash($algo, $str, $raw = false)
    {
        if (null === static::$supportedAlgorithms) 
        {
            static::$supportedAlgorithms = hash_algos();
        }

        if (!in_array(strtolower($algo), static::$supportedAlgorithms))
        {
            throw new \InvalidArgumentException(sprintf('Algorithm "%s" is not supported.', $algo));
        }

        return hash($algo, $str, $raw);
    }

    /**
     * @param string $password
     * @param integer|array $config
     * @return string
     */
    public static function password($password , $config)
    {
        if (is_array($config))
        {
            $algo = isset($config['algo']) ? $config['algo'] : PASSWORD_DEFAULT;
            
            unset($config['algo']);
            $options = $config;
        }
        else
        {
            $algo = $config;
            $options = [];
        }
        
        return password_hash(
            base64_encode(static::hash('sha256', $password, true)),
            $algo,
            $options
        );
    }
    
    /**
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public static function verify($password, $hash) 
    {
        return password_verify(
            base64_encode(static::hash('sha256', $password, true)),
            $hash
        );
    }
}
