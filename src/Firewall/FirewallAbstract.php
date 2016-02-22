<?php

namespace Elixir\Security\Firewall;

use Elixir\Config\ConfigInterface;
use Elixir\Dispatcher\DispatcherTrait;
use Elixir\Security\Auth\AuthManager;
use Elixir\Security\Firewall\AccessControlInterface;
use Elixir\Security\Firewall\FirewallInterface;
use Elixir\Security\Firewall\LoadParser;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */

abstract class FirewallAbstract implements FirewallInterface
{
    use DispatcherTrait;
    
    /**
     * @var integer
     */
    protected $serial = 0;
    
    /**
     * @var boolean
     */
    protected $sorted = false;
    
    /**
     * @var AuthManager
     */
    protected $authManager;
    
    /**
     * @var array
     */
    protected $accessControls = [];
    
    /**
     * @param AuthManager $authManager
     */
    public function __construct(Manager $authManager)
    {
        $this->authManager = $authManager;
    }
    
    /**
     * @return AuthManager
     */
    public function getAuthManager()
    {
        return $this->authManager;
    }
    
    /**
     * @param ConfigInterface $config
     * @param string $key
     */
    public function fromConfig(ConfigInterface $config, $key = null)
    {
        $data = $key ? $config->get($key, []) : $config->all();
        
        foreach (LoadParser::parse($data, get_class($this)) as $config)
        {
            $this->addAccessControl($config['access_control'], $config['priority']);
        }
    }
    
    /**
     * @param ConfigInterface $config
     * @param string $key
     * @return ConfigInterface
     */
    public function toConfig(ConfigInterface $config, $key = null)
    {
        $data = [];

        foreach ($this->allAccessControls(true) as $config)
        {
            $data[$config['access_control']->getPattern()] = [
                'options' => $config['access_control']->getOptions(),
                'priority' => $config['priority']
            ];
        }
        
        if (null !== $key)
        {
            $config->set($key, $data);
        }
        else
        {
            $config->replace($data);
        }
        
        return $config;
    }
    
    /**
     * @param AccessControlInterface $accessControl
     * @return boolean
     */
    public function hasAccessControl(AccessControlInterface $accessControl)
    {
        foreach ($this->accessControls as $value)
        {
            if ($value['access_control'] === $accessControl)
            {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * @param AccessControlInterface $accessControl
     * @param integer $priority
     */
    public function addAccessControl(AccessControlInterface $accessControl, $priority = 0)
    {
        if (!$this->hasAccessControl($accessControl))
        {
            $this->sorted = false;
            
            $this->accessControls[] = [
                'access_control' => $accessControl,
                'priority' =>$priority, 
                'serial' => $this->serial++
            ];
        }
    }
    
    /**
     * @param AccessControlInterface $accessControl
     */
    public function removeAccessControl(AccessControlInterface $accessControl)
    {
        $i = count($this->accessControls);
        
        while ($i--)
        {
            $config = $this->accessControls[$i];
            
            if ($config['access_control'] === $accessControl)
            {
                array_splice($this->accessControls, $i, 1);
                break;
            }
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function allAccessControls($withInfos = false)
    {
        $accessControls = [];
            
        foreach ($this->accessControls as $config)
        {
            $accessControls[] = $withInfos ? $config : $config['access_control'];
        }

        return $accessControls;
    }
    
    /**
     * @param array $accessControls
     */
    public function replaceAccessControls(array $accessControls)
    {
        $this->accessControls = [];
        $this->serial = 0;
        
        foreach ($accessControls as $config)
        {
            $accessControl = $config;
            $priority = 0;
            
            if (is_array($config))
            {
                $accessControl = $config['access_control'];
                
                if (isset($config['priority']))
                {
                    $priority = $config['priority'];
                }
            }
            
            $this->addAccessControl($accessControl, $priority);
        }
    }
    
    /**
     * @return void
     */
    public function sort() 
    {
        if (!$this->sorted)
        {
            uasort($this->accessControls, function (array $p1, array $p2)
            {
                if ($p1['priority'] === $p2['priority']) 
                {
                    return ($p1['serial'] < $p2['serial']) ? -1 : 1;
                }

                return ($p1['priority'] > $p2['priority']) ? -1 : 1;
            });
        
            $this->sorted = true;
        }
    }
    
    /**
     * @return boolean
     */
    public function isSorted()
    {
        return $this->sorted;
    }
    
    /**
     * @param AccessControlInterface|array $accessControls
     */
    public function merge($accessControls)
    {
        if ($accessControls instanceof self) 
        {
            $accessControls = $accessControls->allAccessControls(true);
        }

        if (count($accessControls) > 0) 
        {
            $this->sorted = false;
            
            foreach ($accessControls as $config)
            {
                $priority = 0;
                $serial = 0;

                if (is_array($config))
                {
                    $accessControl = $config['access_control'];

                    if (isset($config['priority']))
                    {
                        $priority = $config['priority'];
                    }

                    if (isset($config['serial'])) 
                    {
                        $serial = $config['serial'];
                    }
                }
                else
                {
                    $accessControl = $config;
                }

                $this->accessControls[] = [
                    'access_control' => $accessControl,
                    'priority' => $priority,
                    'serial' => ($this->_serial++) + $serial
                ];
            }
        }
    }
}
