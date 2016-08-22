<?php

namespace Elixir\Security;

/**
 * @author Cédric Tanghe <ced.tanghe@gmail.com>
 */
class Crypt
{
    /**
     * @var string
     */
    protected $cipher;

    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $mode;

    /**
     * @var int
     */
    protected $ivSize;

    /**
     * @param string $secret
     * @param string $cipher
     * @param string $mode
     *
     * @throws \RuntimeException
     */
    public function __construct($secret, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC)
    {
        if (!extension_loaded('mcrypt')) {
            throw new \RuntimeException('Mcrypt is not available.');
        }

        $this->cipher = $cipher;
        $this->mode = $mode;
        $this->ivSize = mcrypt_get_iv_size($this->cipher, $this->mode);

        $maxSize = mcrypt_get_key_size($this->cipher, $this->mode);
        $this->secret = strlen($secret) > $maxSize ? substr($secret, 0, $maxSize) : $secret;
    }

    /**
     * @return string
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * @return string
     */
    public function getMode()
    {
        return $this->mode;
    }

    /**
     * @param string $str
     *
     * @return string
     */
    public function encrypt($str)
    {
        $iv = mcrypt_create_iv($this->ivSize, MCRYPT_RAND);

        $encripted = mcrypt_encrypt(
            $this->cipher,
            $this->secret,
            $str,
            $this->mode,
            $iv
        );

        return base64_encode($iv.$encripted);
    }

    /**
     * @param string $str
     *
     * @return string
     */
    public function decrypt($str)
    {
        $decode = base64_decode($str);

        return rtrim(
            mcrypt_decrypt(
                $this->cipher,
                $this->secret,
                substr($decode, $this->ivSize),
                $this->mode,
                substr($decode, 0, $this->ivSize)
            ),
            "\0"
        );
    }
}
