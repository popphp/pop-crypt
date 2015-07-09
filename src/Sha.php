<?php
/**
 * Pop PHP Framework (http://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp
 * @category   Pop
 * @package    Pop_Crypt
 * @author     Nick Sagona, III <dev@nolainteractive.com>
 * @copyright  Copyright (c) 2009-2015 NOLA Interactive, LLC. (http://www.nolainteractive.com)
 * @license    http://www.popphp.org/license     New BSD License
 */

/**
 * @namespace
 */
namespace Pop\Crypt;

/**
 * SHA Crypt class
 *
 * @category   Pop
 * @package    Pop_Crypt
 * @author     Nick Sagona, III <dev@nolainteractive.com>
 * @copyright  Copyright (c) 2009-2015 NOLA Interactive, LLC. (http://www.nolainteractive.com)
 * @license    http://www.popphp.org/license     New BSD License
 * @version    2.0.0
 */
class Sha extends AbstractCrypt
{

    /**
     * Bits
     * @var int
     */
    protected $bits = 512;

    /**
     * Rounds
     * @var int
     */
    protected $rounds = 5000;

    /**
     * Constructor
     *
     * Instantiate the sha object.
     *
     * @param  string $salt
     * @param  int    $bits
     * @param  int    $rounds
     * @return self
     */
    public function __construct($salt = null, $bits = 512, $rounds = 5000)
    {
        if ($bits == 512) {
            $this->setBits512();
        } else {
            $this->setBits256();
        }
        $this->setRounds($rounds);
        $this->setSalt($salt);
    }

    /**
     * Method to set the cost to 256 bits
     *
     * @return self
     */
    public function setBits256()
    {
        $this->bits = 256;
        return $this;
    }

    /**
     * Method to set the cost to 512 bits
     *
     * @return self
     */
    public function setBits512()
    {
        $this->bits = 512;
        return $this;
    }

    /**
     * Get the bits
     *
     * @return int
     */
    public function getBits()
    {
        return $this->bits;
    }

    /**
     * Set the rounds
     *
     * @param  int $rounds
     * @return self
     */
    public function setRounds($rounds = 5000)
    {
        $rounds = (int)$rounds;

        if ($rounds < 1000) {
            $rounds = 1000;
        } else if ($rounds > 999999999) {
            $rounds = 999999999;
        }

        $this->rounds = $rounds;
        return $this;
    }

    /**
     * Get the rounds
     *
     * @return int
     */
    public function getRounds()
    {
        return $this->rounds;
    }

    /**
     * Create the hashed value
     *
     * @param  string $string
     * @throws Exception
     * @return string
     */
    public function create($string)
    {
        $hash = null;
        $prefix = ($this->bits == 512) ? '$6$' : '$5$';
        $prefix .= 'rounds=' . $this->rounds . '$';

        $this->salt = (null === $this->salt) ?
            substr(str_replace('+', '.', base64_encode($this->generateRandomString(32))), 0, 16) :
            substr(str_replace('+', '.', base64_encode($this->salt)), 0, 16);

        $hash = crypt($string, $prefix . $this->salt);

        return $hash;
    }

    /**
     * Verify the hashed value
     *
     * @param  string $string
     * @param  string $hash
     * @throws Exception
     * @return boolean
     */
    public function verify($string, $hash)
    {
        $result = crypt($string, $hash);
        return ($result === $hash);
    }

}
