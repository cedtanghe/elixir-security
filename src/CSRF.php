<?php

namespace Elixir\Security;

use Elixir\HTTP\ServerRequestFactory;
use Elixir\Session\Session;
use Psr\Http\Message\ServerRequestInterface;
use function Elixir\STDLib\array_get;
use function Elixir\STDLib\array_remove;
use function Elixir\STDLib\array_set;

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
     * @var array|\ArrayAccess 
     */
    protected $storage;
    
    /**
     * @param ServerRequestInterface $request
     * @param array|\ArrayAccess $storage
     */
    public function __construct(ServerRequestInterface $request = null, $storage = null)
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
     * @return array|\ArrayAccess
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
            'regenerate' => false
        ];
        
        $time = time();
        
        if ($config['time'] instanceof \DateTime) 
        {
            $config['time'] = $config['time']->format('U') - $time;
        } 
        else if (version_compare(phpversion(), '5.5', '>=') && $config['time'] instanceof \DateInterval)
        {
            $config['time'] = $config['time']->format('U');
        }
        else if (!is_numeric($config['time'])) 
        {
            $config['time'] = strtotime($config['time']);
        }

        $token = uniqid(rand(), true);
        
        array_set(
            [self::TOKEN_KEY, $name . $token], 
            [
                'expire' => $time + $config['time'], 
                'time' => $config['time'], 
                'regenerate' => $config['regenerate']
            ], 
            $this->storage
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
        
        if (null === $options['token'])
        {
            $params = $this->request->getParsedBody();
            
            if (!isset($params[$name]))
            {
                $this->invalidate();
                return false;
            }
            else
            {
                $options['token'] = $params[$name];
            }
        }
        
        $error = false;
        $name .= $options['token'];
        $config = array_get([self::TOKEN_KEY, $name], $this->storage, []);
        $time = isset($config['expire']) ? $config['expire'] : 0;

        if (time() > $time)
        {
            $error = true;
        }

        if (!$error && null !== $options['referer'])
        {
            $params = $this->request->getServerParams();

            if (!isset($params['HTTP_REFERER']) || $params['HTTP_REFERER'] !== $options['referer'])
            {
                $error = true;
            }
        }

        $regenerate = array_key_exists('regenerate', $config) ? $config['regenerate'] : false;

        if ($error || !$regenerate)
        {
            array_remove([self::TOKEN_KEY, $name], $this->storage);
        }
        else if ($regenerate)
        {
            $config['expire'] = time() + $config['time'];
            array_set([self::TOKEN_KEY, $name], $config, $this->storage);
        }
        
        $this->invalidate();
        return !$error;
    }

    /**
     * @return void
     */
    public function invalidate() 
    {
        $tokens = array_get(self::TOKEN_KEY, $this->storage, []);
        $time = time();

        foreach ($tokens as $key => $config)
        {
            $expire = isset($config['expire']) ? $config['expire'] : 0;
            
            if ($time > $value)
            {
                unset($tokens[$key]);
            }
        }

        array_set(self::TOKEN_KEY, $tokens, $this->storage);
    }
}
