<?php
/**
 * Pop PHP Framework (https://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp-framework
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 */

/**
 * @namespace
 */
namespace Pop\Crypt\Hashing;

/**
 * Pop Crypt Bcrypt hasher
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
 */
class BcryptHasher extends AbstractHasher
{

    /**
     * Cost
     * @var int
     */
    protected int $cost = 12;

    /**
     * Constructor
     *
     * Instantiate the Bcrypt object
     *
     * @param int     $cost
     * @param ?string $salt
     */
    public function __construct(int $cost = 12)
    {
        $this->setCost($cost);
    }

    /**
     * Set cost
     *
     * @param  int $cost
     * @return BcryptHasher
     */
    public function setCost(int $cost): BcryptHasher
    {
        $this->cost = $cost;
        return $this;
    }

    /**
     * Get cost
     *
     * @return int
     */
    public function getCost(): int
    {
        return $this->cost;
    }

    /**
     * Has cost
     *
     * @return bool
     */
    public function hasCost(): bool
    {
        return !empty($this->cost);
    }

    /**
     * Make hashed value (based on the hasher class)
     *
     * @param  string $value
     * @return string
     */
    public function make(#[\SensitiveParameter] string $value): string
    {
        return $this->createHash($value, PASSWORD_BCRYPT,  ['cost' => $this->getCost()]);
    }

    /**
     * Determine if the hashed value requires re-hashing (based on the hasher class)
     *
     * @param  string $hashedValue
     * @return bool
     */
    public function requiresRehash(string $hashedValue): bool
    {
        return $this->needsRehash($hashedValue, PASSWORD_BCRYPT, ['cost' => $this->getCost()]);
    }

    /**
     * Set hasher options
     *
     * @param  array $options
     * @return static
     */
    public function setOptions(array $options): static
    {
        if (isset($options['cost'])) {
            $this->setCost($options['cost']);
        }
        return $this;
    }

}
