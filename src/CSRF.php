<?php

namespace Elixir\Security;

use Elixir\HTTP\ServerRequestFactory;
use Elixir\HTTP\ServerRequestInterface;
use Elixir\Session\Session;
use Elixir\Session\SessionInterface;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class CSRF 
{
    /**
     * @var integer
     */
    const DEFAULT_TIME = 3600;

    /**
     * @var string
     */
    const TOKEN_KEY = '___CSRF___';

    /**
     * @var ServerRequestInterface 
     */
    protected $request;
    
    /**
     * @var SessionInterface 
     */
    protected $storage;
    
    /**
     * @param ServerRequestInterface $request
     * @param SessionInterface $storage
     */
    public function __construct(ServerRequestInterface $request = null, SessionInterface $storage = null)
    {
        $this->request = $request ?: ServerRequestFactory::createFromGlobals();
        $this->storage = $storage ?: Session::instance();
    }

    /**
     * @return ServerRequestInterface
     */
    public function getRequest()
    {
        return $this->request;
    }
    
    /**
     * @return SessionInterface
     */
    public function getStorage()
    {
        return $this->storage;
    }

    /**
     * @param string $name
     * @param array $config
     * @return string
     */
    public function create($name, array $config = [])
    {
        $config += [
            'time' => self::DEFAULT_TIME,
            'consumable' => true
        ];
        
        if ($config['time'] instanceof \DateTime) 
        {
            $config['time'] = $pTime->format('U');
        } 
        else if (!is_numeric($config['time'])) 
        {
            $config['time'] = strtotime($pTime);
        }

        $token = uniqid(rand(), true);
        
        $this->storage->set(
            [self::TOKEN_KEY, $name . $token],
            ['expire' => time() . $config['time'], 'consumable' => $config['consumable']]
        );

        return $token;
    }
    
    /**
     * @param string $name
     * @param array $options
     * @return boolean
     */
    public function isValid($name, array $options = [])
    {
        $options += [
            'referer' => null,
            'token' => null
        ];
        
        $error = false;
        
        if (null === $options['token'])
        {
            $params = $this->request->getParsedBody();
            
            if (!isset($params[$name]))
            {
                $error = true;
            }
            else
            {
                $options['token'] = $params[$name];
            }
        }
        
        if (!$error) 
        {
            $name .= $options['token'];
            $config = $this->storage->get([self::TOKEN_KEY, $name], []);
            $time = isset($config['expire']) ? $config['expire'] : null;

            if (null === $time) 
            {
                $error = true;
            }

            if (!$error) 
            {
                $consumable = array_key_exists(consumable, $config) ? $config['consumable'] : true;
                
                if ($consumable)
                {
                    $this->storage->remove([self::TOKEN_KEY, $name]);
                }
                
                if (time() > $time)
                {
                    $error = true;
                }

                if (!$error)
                {
                    if (null !== $options['referer']) 
                    {
                        $params = $this->request->getServerParams();
                        
                        if (!isset($params['HTTP_REFERER']) || $params['HTTP_REFERER'] !== $options['referer'])
                        {
                            $error = true;
                        }
                    }
                }
            }
        }
        
        $this->invalidate();
        return !$error;
    }

    /**
     * @return void
     */
    public function invalidate() 
    {
        $tokens = $this->storage->get(self::TOKEN_KEY, []);
        $time = time();

        foreach ($tokens as $key => $config)
        {
            $expire = isset($config['expire']) ? $config['expire'] : 0;
            
            if ($time > $value)
            {
                unset($tokens[$key]);
            }
        }

        $this->storage->set(self::TOKEN_KEY, $tokens);
    }
}
