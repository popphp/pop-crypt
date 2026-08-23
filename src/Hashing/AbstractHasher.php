<?php
declare(strict_types=1);
/**
 * Pop PHP Framework (https://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp-framework
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2026 Nick Sagona, III
 * @license    https://www.popphp.org/license     New BSD License
 */

/**
 * @namespace
 */
namespace Pop\Crypt\Hashing;

/**
 * Pop Crypt abstract hasher
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2026 Nick Sagona, III
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
 */
abstract class AbstractHasher
{

    /**
     * Maximum allowed length, in bytes, for a value passed to createHash() or verify().
     *
     * Argon2's cost scales with input size, so without a cap an attacker-controlled
     * value of unbounded length becomes an algorithmic-complexity denial-of-service
     * vector. 4096 matches the limit used by Symfony's password hasher.
     */
    const MAX_VALUE_LENGTH = 4096;

    /**
     * Make hashed value (based on the hasher class)
     *
     * @param  string $value
     * @return string
     */
    abstract public function make(#[\SensitiveParameter] string $value): string;

    /**
     * Determine if the hashed value requires re-hashing (based on the hasher class)
     *
     * @param  string $hashedValue
     * @return bool
     */
    abstract public function requiresRehash(string $hashedValue): bool;

    /**
     * Set hasher options
     *
     * @param  array $options
     * @return static
     */
    abstract public function setOptions(array $options): static;

    /**
     * Create hasher object with options
     *
     * @return static
     */
    public static function create(array $options = []): static
    {
        $hasher = new static();
        $hasher->setOptions($options);
        return $hasher;
    }

    /**
     * Create hashed value
     *
     * @param  string          $value
     * @param  string|int|null $algorithm
     * @param  array           $options
     * @throws Exception
     * @return string
     */
    public function createHash(#[\SensitiveParameter] string $value, string|int|null $algorithm, array $options = []): string
    {
        if (strlen($value) > static::MAX_VALUE_LENGTH) {
            throw new Exception('Error: The value exceeds the maximum allowed length of ' . static::MAX_VALUE_LENGTH . ' bytes.');
        }
        return password_hash($value, $algorithm, $options);
    }

    /**
     * Get info from hashed value
     *
     * @param  string $hashedValue
     * @return array
     */
    public function getInfo(string $hashedValue): array
    {
        return password_get_info($hashedValue);
    }

    /**
     * Get available hashing algorithms
     *
     * @return array
     */
    public function getAlgorithms(): array
    {
        return password_algos();
    }

    /**
     * Determine if the hashed value needs to be re-hashed
     *
     * @param  string          $hashedValue
     * @param  string|int|null $algorithm
     * @param  array           $options
     * @return bool
     */
    public function needsRehash(string $hashedValue, string|int|null $algorithm, array $options = []): bool
    {
        return password_needs_rehash($hashedValue, $algorithm, $options);
    }

    /**
     * Verify hash
     *
     * @param  string $value
     * @param  string $hashedValue
     * @throws Exception
     * @return bool
     */
    public function verify(#[\SensitiveParameter] string $value, string $hashedValue): bool
    {
        if (strlen($value) > static::MAX_VALUE_LENGTH) {
            throw new Exception('Error: The value exceeds the maximum allowed length of ' . static::MAX_VALUE_LENGTH . ' bytes.');
        }
        return password_verify($value, $hashedValue);
    }

}
