<?php

namespace Elixir\Security;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class MaskBuilder
{
    /**
     * @var int
     */
    protected $code;

    /**
     * @param int $code
     */
    public function __construct($code = 0)
    {
        $this->code = $code;
    }

    /**
     * @return int
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * @param int $code
     *
     * @return bool
     */
    public function has($code)
    {
        return ($this->code & $code) !== 0;
    }

    /**
     * @param int $code
     */
    public function add($code)
    {
        if (!$this->has($code)) {
            $this->code |= $code;
        }
    }

    /**
     * @param int $code
     */
    public function remove($code)
    {
        if (!$this->has($code)) {
            $this->code ^= $code;
        }
    }

    /**
     * @param array $references
     *
     * @return array
     */
    public function getCodes(array $references)
    {
        $codes = [];

        foreach ($references as $code) {
            if ($this->has($code)) {
                $codes[] = $code;
            }
        }

        return $codes;
    }
}
