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
namespace Pop\Crypt\Encryption;

/**
 * Pop Crypt encrypter interface
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
 */
interface EncrypterInterface
{

    /**
     * Set cipher
     *
     * @param  string $cipher
     * @return static
     */
    public function setCipher(string $cipher): static;

    /**
     * Get cipher
     *
     * @return string
     */
    public function getCipher(): string;

    /**
     * Has cipher
     *
     * @return bool
     */
    public function hasCipher(): bool;

    /**
     * Set key
     *
     * @param  string $key
     * @return static
     */
    public function setKey(string $key): static;

    /**
     * Get key
     *
     * @return string
     */
    public function getKey(): string;

    /**
     * Has key
     *
     * @return bool
     */
    public function hasKey(): bool;

    /**
     * Get all keys
     *
     * @return array
     */
    public function getAllKeys(): array;

    /**
     * Set previous keys
     *
     * @param  array $previousKeys
     * @throws Exception
     * @return static
     */
    public function setPreviousKeys(array $previousKeys): static;

    /**
     * Get previous keys
     *
     * @return array
     */
    public function getPreviousKeys(): array;

    /**
     * Has previous keys
     *
     * @return bool
     */
    public function hasPreviousKeys(): bool;

    /**
     * Determine if the cipher is available
     *
     * @param  string $cipher
     * @return bool
     */
    public static function isAvailable(string $cipher);

    /**
     * Determine if the key and cipher combination is valid
     *
     * @param  string $key
     * @param  string $cipher
     * @return bool
     */
    public static function isValid(string $key, string $cipher): bool;

    /**
     * Encrypt value
     *
     * @param  mixed $value
     * @return string
     */
    public function encrypt(mixed $value): string;

    /**
     * Decrypt value
     *
     * @param  mixed $payload
     * @return mixed
     */
    public function decrypt(mixed $payload): mixed;

}
