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
 * Pop Crypt Abstract Argon2 class
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
 */
abstract class AbstractArgon2Hasher extends AbstractHasher
{

    /**
     * Memory cost
     * @var int
     */
    protected int $memoryCost = PASSWORD_ARGON2_DEFAULT_MEMORY_COST; // 65536

    /**
     * Time cost
     * @var int
     */
    protected int $timeCost = PASSWORD_ARGON2_DEFAULT_TIME_COST; // 4

    /**
     * Threads
     * @var int
     */
    protected int $threads = PASSWORD_ARGON2_DEFAULT_THREADS; // 1

    /**
     * Constructor
     *
     * Instantiate the Argon2 object
     *
     * @param int $memoryCost
     * @param int $timeCost
     * @param int $threads
     */
    public function __construct(
        int $memoryCost = PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        int $timeCost = PASSWORD_ARGON2_DEFAULT_TIME_COST,
        int $threads = PASSWORD_ARGON2_DEFAULT_THREADS
    )
    {
        $this->setMemoryCost($memoryCost);
        $this->setTimeCost($timeCost);
        $this->setThreads($threads);
    }

    /**
     * Set memory cost
     *
     * @param  int $memoryCost
     * @return static
     */
    public function setMemoryCost(int $memoryCost): static
    {
        $this->memoryCost = $memoryCost;
        return $this;
    }

    /**
     * Get memory cost
     *
     * @return int
     */
    public function getMemoryCost(): int
    {
        return $this->memoryCost;
    }

    /**
     * Has memory cost
     *
     * @return bool
     */
    public function hasMemoryCost(): bool
    {
        return !empty($this->memoryCost);
    }

    /**
     * Set time cost
     *
     * @param  int $timeCost
     * @return static
     */
    public function setTimeCost(int $timeCost): static
    {
        $this->timeCost = $timeCost;
        return $this;
    }

    /**
     * Get time cost
     *
     * @return int
     */
    public function getTimeCost(): int
    {
        return $this->timeCost;
    }

    /**
     * Has time cost
     *
     * @return bool
     */
    public function hasTimeCost(): bool
    {
        return !empty($this->timeCost);
    }

    /**
     * Set threads
     *
     * @param  int $threads
     * @return static
     */
    public function setThreads(int $threads): static
    {
        $this->threads = $threads;
        return $this;
    }

    /**
     * Get threads
     *
     * @return int
     */
    public function getThreads(): int
    {
        return $this->threads;
    }

    /**
     * Has threads
     *
     * @return bool
     */
    public function hasThreads(): bool
    {
        return !empty($this->threads);
    }

    /**
     * Set hasher options
     *
     * @param  array $options
     * @return static
     */
    public function setOptions(array $options): static
    {
        if (isset($options['memory_cost'])) {
            $this->setMemoryCost($options['memory_cost']);
        }
        if (isset($options['time_cost'])) {
            $this->setTimeCost($options['time_cost']);
        }
        if (isset($options['threads'])) {
            $this->setThreads($options['threads']);
        }
        return $this;
    }

}
