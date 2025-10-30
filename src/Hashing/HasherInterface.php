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
 * Pop Crypt hashing interface
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
 */
interface HasherInterface
{

    /**
     * Make hashed value (based on the hasher class)
     *
     * @param  string $value
     * @return string
     */
    public function make(#[\SensitiveParameter] string $value): string;

    /**
     * Determine if the hashed value requires re-hashing (based on the hasher class)
     *
     * @param  string $hashedValue
     * @return bool
     */
    public function requiresRehash(string $hashedValue): bool;

    /**
     * Set hasher options
     *
     * @param  array $options
     * @return static
     */
    public function setOptions(array $options): static;

    /**
     * Create hasher object with options
     *
     * @return static
     */
    public static function createHasher(array $options = []): static;

    /**
     * Create hashed value
     *
     * @param  string          $value
     * @param  string|int|null $algorithm
     * @param  array           $options
     * @return string
     */
    public function create(#[\SensitiveParameter] string $value, string|int|null $algorithm, array $options = []): string;

    /**
     * Get info from hashed value
     *
     * @param  string $hashedValue
     * @return array
     */
    public function getInfo(string $hashedValue): array;

    /**
     * Get available hashing algorithms
     *
     * @return array
     */
    public function getAlgorithms(): array;

    /**
     * Determine if the hashed value needs to be re-hashed
     *
     * @param  string          $hashedValue
     * @param  string|int|null $algorithm
     * @param  array           $options
     * @return bool
     */
    public function needsRehash(string $hashedValue, string|int|null $algorithm, array $options = []): bool;

    /**
     * Verify hash
     *
     * @param  string $value
     * @param  string $hashedValue
     * @return bool
     */
    public function verify(#[\SensitiveParameter] string $value, string $hashedValue): bool;

}
