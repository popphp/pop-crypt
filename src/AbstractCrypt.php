<?php
/**
 * Pop PHP Framework (http://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp-framework
 * @author     Nick Sagona, III <dev@nolainteractive.com>
 * @copyright  Copyright (c) 2009-2015 NOLA Interactive, LLC. (http://www.nolainteractive.com)
 * @license    http://www.popphp.org/license     New BSD License
 */

/**
 * @namespace
 */
namespace Pop\Crypt;

/**
 * Crypt interface
 *
 * @category   Pop
 * @package    Pop_Crypt
 * @author     Nick Sagona, III <dev@nolainteractive.com>
 * @copyright  Copyright (c) 2009-2015 NOLA Interactive, LLC. (http://www.nolainteractive.com)
 * @license    http://www.popphp.org/license     New BSD License
 * @version    2.0.0
 */
abstract class AbstractCrypt implements CryptInterface
{

    /**
     * Salt
     * @var string
     */
    protected $salt = null;

    /**
     * Set the salt
     *
     * @param  string $salt
     * @return self
     */
    public function setSalt($salt = null)
    {
        $this->salt = $salt;
        return $this;
    }

    /**
     * Get the salt
     *
     * @return string
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * Generate a random alphanumeric string of a predefined length.
     *
     * @param  int $length
     * @return string
     */
    public function generateRandomString($length)
    {
        $str   = null;
        $chars = str_split('abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789');

        for ($i = 0; $i < $length; $i++) {
            $index = mt_rand(0, (count($chars) - 1));
            $str .= $chars[$index];
        }

        return $str;
    }

    /**
     * Get string length
     *
     * @param  string $string
     * @return int
     */
    protected function strlen($string)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($string, '8bit');
        } else {
            return strlen($string);
        }
    }

    /**
     * Verify hash, timing-safe.
     * Credit: Anthony Ferrara's (ircmaxell) password compat library:
     * https://github.com/ircmaxell/password_compat
     *
     * @param  string $string
     * @param  string $hash
     * @return boolean
     */
    protected function verifyHash($string, $hash)
    {
        $status = 0;

        for ($i = 0; $i < $this->strlen($string); $i++) {
            $status |= (ord($string[$i]) ^ ord($hash[$i]));
        }

        return $status === 0;
    }

}
