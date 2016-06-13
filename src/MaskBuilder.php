<?php

namespace Elixir\Security;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class MaskBuilder 
{
    /**
     * @var integer 
     */
    protected $code;

    /**
     * @param integer $code
     */
    public function __construct($code = 0) 
    {
        $this->code = $code;
    }
    
    /**
     * @return integer
     */
    public function getCode() 
    {
        return $this->code;
    }
    
    /**
     * @param integer $code
     * @return boolean
     */
    public function has($code) 
    {
        return ($this->code & $code) !== 0;
    }

    /**
     * @param integer $code
     */
    public function add($code) 
    {
        if (!$this->has($code)) 
        {
            $this->code |= $code;
        }
    }

    /**
     * @param integer $code
     */
    public function remove($code) 
    {
        if (!$this->has($code)) 
        {
            $this->code ^= $code;
        }
    }
    
    /**
     * @param array $references
     * @return array
     */
    public function getCodes(array $references)
    {
        $codes = [];

        foreach ($references as $code) 
        {
            if ($this->has($code)) 
            {
                $codes[] = $code;
            }
        }

        return $codes;
    }
}
