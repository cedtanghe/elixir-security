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
    public static function password($password, $config = null)
    {
        if (is_array($config))
        {
            $algo = isset($config['algo']) ? $config['algo'] : PASSWORD_DEFAULT;
            
            unset($config['algo']);
            $options = $config;
        }
        else if (!empty($config))
        {
            $algo = $config;
            $options = [];
        }
        else
        {
            $algo = PASSWORD_DEFAULT;
            $options = [];
        }
        
        return password_hash($password, $algo, $options);
    }
    
    /**
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public static function validate($password, $hash) 
    {
        return password_verify($password, $hash);
    }
    
    /**
     * @param string $hash
     * @param integer|array $config
     * @return boolean
     */
    public static function needsRehash($hash, $config = null) 
    {
        if (is_array($config))
        {
            $algo = isset($config['algo']) ? $config['algo'] : PASSWORD_DEFAULT;
            
            unset($config['algo']);
            $options = $config;
        }
        else if (!empty($config))
        {
            $algo = $config;
            $options = [];
        }
        else
        {
            $infos = static::hashInfo($hash);
            $algo = $infos['algo'];
            $options = $infos['options'];
        }
        
        return password_needs_rehash($hash, $algo, $options);
    }
    
    /**
     * @param string $hash
     * @return array
     */
    public static function hashInfo($hash) 
    {
        return password_get_info($hash);
    }
}
