<?php
/**
 * Pop PHP Framework (http://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp-framework
 * @author     Nick Sagona, III <dev@nolainteractive.com>
 * @copyright  Copyright (c) 2009-2016 NOLA Interactive, LLC. (http://www.nolainteractive.com)
 * @license    http://www.popphp.org/license     New BSD License
 */

/**
 * @namespace
 */
namespace Pop\Crypt;

/**
 * Crypt class
 *
 * @category   Pop
 * @package    Pop_Crypt
 * @author     Nick Sagona, III <dev@nolainteractive.com>
 * @copyright  Copyright (c) 2009-2016 NOLA Interactive, LLC. (http://www.nolainteractive.com)
 * @license    http://www.popphp.org/license     New BSD License
 * @version    2.0.0
 */
class Crypt extends AbstractCrypt
{

    /**
     * Constructor
     *
     * Instantiate the crypt object.
     *
     * @param  string $salt
     * @return self
     */
    public function __construct($salt = null)
    {
        $this->setSalt($salt);
    }

    /**
     * Create the hashed value
     *
     * @param  string $string
     * @return string
     */
    public function create($string)
    {
        $hash = (null !== $this->salt) ? crypt($string, $this->salt) : crypt($string);
        return $hash;
    }

    /**
     * Verify the hashed value
     *
     * @param  string $string
     * @param  string $hash
     * @return boolean
     */
    public function verify($string, $hash)
    {
        $result = crypt($string, $hash);

        if (!is_string($string) || !is_string($result) || (strlen($result) != strlen($hash))) {
            return false;
        } else {
            return $this->verifyHash($result, $hash);
        }
    }

}
