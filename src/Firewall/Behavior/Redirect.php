<?php

namespace Elixir\Security\Firewall\Behavior;

use Elixir\HTTP\ResponseFactory;
use Elixir\Security\Firewall\Behavior\BehaviorInterface;
use Elixir\Security\Firewall\FirewallInterface;
use Elixir\Session\Session;
use Elixir\Session\SessionInterface as SessionInterface;
use Elixir\STDLib\Facade\I18N;
use function Elixir\STDLib\array_get;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Redirect implements BehaviorInterface
{
    /**
     * @var string 
     */
    protected $message;

    /**
     * @var string
     */
    protected $redirectURL;
    
    /**
     * @var string
     */
    protected $currentURL;
    
    /**
     * @var SessionInterface
     */
    protected $session;

    /**
     * @param string $redirectURL
     * @param string $currentURL
     * @param string $message
     * @param SessionInterface $session
     */
    public function __construct($redirectURL, $currentURL = null, $message = null, SessionInterface $session = null)
    {
        $this->redirectURL = $redirectURL;
        $this->currentURL = $currentURL;
        
        if (!$this->currentURL)
        {
            $URI = '';
            $HTTPS = array_get('HTTPS', $_SERVER);

            if ($HTTPS && $HTTPS !== 'on' || array_get('HTTP_X_FORWARDED_PROTO', $_SERVER) === 'https')
            {
                $URI = 'https://';
            }
            else
            {
                $URI = 'http://';
            }

            $URI .= array_get('HTTP_HOST', $_SERVER, '');
            $URI .= array_get('REQUEST_URI', $_SERVER, '');

            $this->currentURL = $URI;
        }
        
        $this->message = $message ? : I18N::__('Please log in.', ['context' => 'elixir']);
        $this->session = $session ?: Session::instance();
    }
    
    /**
     * @return string
     */
    public function getRedirectURL()
    {
        return $this->redirectURL;
    }
    
    /**
     * @return string
     */
    public function getCurrentURL()
    {
        return $this->currentURL;
    }

    /**
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * @return SessionInterface
     */
    public function getSession()
    {
        return $this->session;
    }

    /**
     * {@inheritdoc}
     */
    public function __invoke(FirewallInterface $firewall)
    {
        $this->session->flash(SessionInterface::FLASH_REDIRECT, $this->currentURL);
        $this->session->flash(SessionInterface::FLASH_INFO, $this->message);
        
        return ResponseFactory::createRedirect($this->redirectURL, 302, [], false);
    }
}
