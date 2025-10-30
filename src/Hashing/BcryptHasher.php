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
     * Salt
     * @var ?string
     */
    protected ?string $salt = null;

    /**
     * Cost
     * @var int
     */
    protected int $cost = 12;

    /**
     * Constructor
     *
     * Instantiate the Bcrypt object
     */
    public function __construct(int $cost = 12, ?string $salt = null)
    {
        $this->setCost($cost);
        if ($salt !== null) {
            $this->setSalt($salt);
        }
    }

    /**
     * Set salt
     *
     * @param  string $salt
     * @return BcryptHasher
     */
    public function setSalt(string $salt): BcryptHasher
    {
        $this->salt = $salt;
        return $this;
    }

    /**
     * Get salt
     *
     * @return ?string
     */
    public function getSalt(): ?string
    {
        return $this->salt;
    }

    /**
     * Has salt
     *
     * @return bool
     */
    public function hasSalt(): bool
    {
        return !empty($this->salt);
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
        $options = ['cost' => $this->getCost()];
        if ($this->hasSalt()) {
            $options['salt'] = $this->getSalt();
        }
        return $this->create($value, PASSWORD_BCRYPT, $options);
    }

    /**
     * Determine if the hashed value requires re-hashing (based on the hasher class)
     *
     * @param  string $hashedValue
     * @return bool
     */
    public function requiresRehash(string $hashedValue): bool
    {
        $options = ['cost' => $this->getCost()];
        if ($this->hasSalt()) {
            $options['salt'] = $this->getSalt();
        }
        return $this->needsRehash($hashedValue, PASSWORD_BCRYPT, $options);
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
        if (isset($options['salt'])) {
            $this->setSalt($options['salt']);
        }
        return $this;
    }

}
