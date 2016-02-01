<?php

namespace Elixir\Security\Auth;

use Elixir\Security\Auth\Identity;
use Elixir\STDLib\Facade\I18N;
use Elixir\STDLib\MessagesCatalog;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Result 
{
    /**
     * @var integer
     */
    const SUCCESS = 1;

    /**
     * @var integer
     */
    const FAILURE = 2;

    /**
     * @var integer
     */
    const IDENTITY_NOT_FOUND = 4;

    /**
     * @var integer
     */
    const CREDENTIAL_INVALID = 8;

    /**
     * @var integer
     */
    const UNKNOWN = 16;

    /**
     * @var integer
     */
    protected $code;

    /**
     * @var Identity
     */
    protected $identity;

    /**
     * @var MessagesCatalog 
     */
    protected $messagesCatalog;
    
    /**
     * @param integer $code
     * @param Identity $identity
     * @param MessagesCatalogog $messagesCatalog
     */
    public function __construct($code, Identity $identity = null, MessagesCatalogog $messagesCatalog = null)
    {
        $this->code = $code;
        $this->identity = $identity;
        
        $messagesCatalog = $messagesCatalog ?: MessagesCatalog::instance();
        $this->messagesCatalog = clone $messagesCatalog;
        
        foreach ($this->getDefaultCatalogMessages() as $key => $value)
        {
            if (!$this->messagesCatalog->has($key))
            {
                $this->messagesCatalog->set($key, $value);
            }
        }
    }
    
    /**
     * @return array
     */
    public function getDefaultCatalogMessages()
    {
        return [
            self::SUCCESS => I18N::__('Successfully performed authentication.', ['context' => 'elixir']),
            self::FAILURE => I18N::__('Unable to authenticate.', ['context' => 'elixir']),
            self::IDENTITY_NOT_FOUND => I18N::__('Identity not found.', ['context' => 'elixir']),
            self::CREDENTIAL_INVALID => I18N::__('Credential invalid.', ['context' => 'elixir']),
            self::UNKNOWN => I18N::__('Unknown error.', ['context' => 'elixir'])
        ];
    }

    /**
     * @return boolean
     */
    public function isSuccess()
    {
        return $this->hasCode(self::SUCCESS);
    }

    /**
     * @return boolean
     */
    public function isFailure() 
    {
        return !$this->isSuccess();
    }

    /**
     * @return integer
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * @var integer
     * @return boolean
     */
    public function hasCode($code) 
    {
        return ($this->code & $code) === $code;
    }
    
    /**
     * @return Identity
     */
    public function getIdentity() 
    {
        return $this->identity;
    }

    /**
     * @return MessagesCatalog
     */
    public function getMessagesCatalog()
    {
        return $this->messagesCatalog;
    }
    
    /**
     * @param integer $code
     * @return string
     */
    public function getMessage($code)
    {
        return $this->messagesCatalog->get($code);
    }
    
    /**
     * @return string
     */
    public function getErrorMessage()
    {
        if ($this->isFailure())
        {
            if ($this->hasCode(self::IDENTITY_NOT_FOUND))
            {
                return $this->getMessage(self::IDENTITY_NOT_FOUND);
            }
            else if ($this->hasCode(self::CREDENTIAL_INVALID))
            {
                return $this->getMessage(self::CREDENTIAL_INVALID);
            }
            else
            {
                return $this->getMessage(self::UNKNOWN);
            }
        }
        
        return null;
    }
}
