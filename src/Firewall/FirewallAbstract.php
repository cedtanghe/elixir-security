<?php

namespace Elixir\Security\Firewall;

use Elixir\Config\Cache\CacheableInterface;
use Elixir\Config\Loader\LoaderFactory;
use Elixir\Config\Loader\LoaderFactoryAwareTrait;
use Elixir\Config\Writer\WriterInterface;
use Elixir\Dispatcher\DispatcherTrait;
use Elixir\Security\Auth\AuthManager;
use Elixir\Security\Firewall\AccessControlInterface;
use Elixir\Security\Firewall\Behavior\BehaviorInterface;
use Elixir\Security\Firewall\FirewallInterface;
use Elixir\Security\Firewall\LoadParser;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
abstract class FirewallAbstract implements FirewallInterface, CacheableInterface
{
    use LoaderFactoryAwareTrait;
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
     * @var CacheableInterface 
     */
    protected $cache;
    
    /**
     * @var AuthManager
     */
    protected $authManager;
    
    /**
     * @var array
     */
    protected $accessControls = [];
    
    /**
     * @var BehaviorInterface 
     */
    protected $failedBehavior;
    
    /**
     * @var BehaviorInterface 
     */
    protected $successBehavior;
    
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
     * @param CacheableInterface $value
     */
    public function setCacheStrategy(CacheableInterface $value)
    {
        $this->cache = $value;
    }
    
    /**
     * @return CacheableInterface
     */
    public function getCacheStrategy()
    {
        return $this->cache;
    }
    
    /**
     * {@inheritdoc}
     */
    public function loadCache()
    {
        if (null === $this->cache)
        {
            return false;
        }
        
        $data = $this->cache->loadCache();
        
        if ($data)
        {
            $data = LoadParser::parse($data, get_class($this));
            
            foreach ($data as $config)
            {
                $this->addAccessControl($config['access_control'], $config['priority']);
            }
        }
        
        return $data;
    }
    
    /**
     * {@inheritdoc}
     */
    public function cacheLoaded()
    {
        if (null === $this->cache)
        {
            return false;
        }
        
        return $this->cache->cacheLoaded();
    }
    
    /**
     * {@inheritdoc}
     */
    public function setFailedBehavior(BehaviorInterface $behavior)
    {
        $this->failedBehavior = $behavior;
    }
    
    /**
     * {@inheritdoc}
     */
    public function setSucessBehavior(BehaviorInterface $behavior)
    {
        $this->successBehavior = $behavior;
    }
    
    /**
     * {@inheritdoc}
     */
    public function applyBehavior($authorize)
    {
        if ($authorize)
        {
            if (null !== $this->successBehavior)
            {
                $behavior = $this->successBehavior;
                return $behavior($this);
            }
        }
        else
        {
            if (null !== $this->failedBehavior)
            {
                $behavior = $this->failedBehavior;
                return $behavior($this);
            }
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function load($config, array $options = [])
    {
        if ($this->cacheLoaded() && $this->isFreshCache())
        {
            return;
        }
        
        if ($config instanceof self)
        {
            $this->merge($config);
        } 
        else 
        {
            if (is_callable($config))
            {
                $data = call_user_func_array($config, [$this]);
            }
            else
            {
                if (null === $this->loaderFactory)
                {
                    $this->loaderFactory = new LoaderFactory();
                    LoaderFactory::addProvider($this->loaderFactory);
                }
                
                $loader = $this->loaderFactory->create($config);
                $data = $loader->load($config);
            }
            
            $data = LoadParser::parse($data, get_class($this));
            
            foreach ($data as $config)
            {
                $this->addAccessControl($config['access_control'], $config['priority']);
            }
        }
    }
    
    /**
     * {@inheritdoc}
     */
    public function export(WriterInterface $writer, $file)
    {
        return $writer->export($this->getExportableData(), $file);
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
     * {@inheritdoc}
     */
    public function isFreshCache()
    {
        if (null === $this->cache)
        {
            return false;
        }
        
        return $this->cache->isFreshCache();
    }
    
    /**
     * {@inheritdoc}
     */
    public function exportToCache(array $data = null)
    {
        if (null === $this->cache)
        {
            return false;
        }
        
        if ($data)
        {
            $data = LoadParser::parse($data, get_class($this));
            
            foreach ($data as $config)
            {
                $this->addAccessControl($config['access_control'], $config['priority']);
            }
        }
        
        return $this->cache->exportToCache($this->getExportableData());
    }
    
    /**
     * {@inheritdoc}
     */
    public function invalidateCache()
    {
        if (null === $this->cache)
        {
            return false;
        }
        
        return $this->cache->invalidateCache();
    }
    
    /**
     * @return array
     */
    protected function getExportableData()
    {
        $data = [];

        foreach ($this->allAccessControls(true) as $config)
        {
            $data[$config['access_control']->getPattern()] = [
                'options' => $config['access_control']->getOptions(),
                'priority' => $config['priority']
            ];
        }
        
        return $data;
    }
    
    /**
     * @param FirewallInterface $firewall
     */
    public function merge(FirewallInterface $firewall)
    {
        $accessControls = $firewall->allAccessControls(true);

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
