<?php

namespace Elixir\Security\Firewall;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Parser 
{
    /**
     * @param array $data
     * @param string $classType
     * @return array
     */
    public static function parse(array $data, $classType) 
    {
        $accessControls = [];

        foreach ($data as $key => $config) 
        {
            if ($key === AccessControlInterface::GLOBAL_CONFIG)
            {
                continue;
            }
            
            $pattern = $key;
            
            $parsed = Parser::parseAccessControl($config);
            $options = $parsed['options'];
            $priority = $parsed['priority'];
            
            if (isset($data[AccessControlInterface::GLOBAL_CONFIG]))
            {
                $options = array_merge($options, $data[AccessControlInterface::GLOBAL_CONFIG]);
            }
            
            $accessControls[] = [
                'access_control' => new $classType($pattern, $options),
                'priority' => $priority
            ];
        }
        
        return $accessControls;
    }
    
    /**
     * @param array $config
     * @return array
     */
    public static function parseAccessControl(array $config)
    {
        $options = [];
        $priority = 0;
        
        foreach ($config as $key => $value)
        {
            if ($key === AccessControlInterface::PRIORITY)
            {
                $priority = $value;
            }
            else if ($key === AccessControlInterface::OPTIONS)
            {
                $options = array_merge($options, $value);
            }
            else
            {
                $options[$key] = $value;
            }
        }
        
        return [
            'options' => $options,
            'priority' => $priority
        ];
    }
}
