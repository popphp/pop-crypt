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
 * Pop Crypt abstract encrypter
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
 */
abstract class AbstractEncrypter
{

    /**
     * Encryption cipher
     * @var string
     */
    protected string $cipher = 'aes-256-cbc';

    /**
     * Encryption Key
     * @var ?string
     */
    protected ?string $key = null;

    /**
     * Previous keys
     * @var array
     */
    protected array $previousKeys = [];

    /**
     * Constructor
     *
     * Instantiate the Encrypter object
     *
     * @param  string $key
     * @param  string $cipher
     * @param  bool   $raw
     * @throws Exception
     */
    public function __construct(string $key, string $cipher = 'aes-256-cbc', bool $raw = true)
    {
        if (!static::isValid($key, $cipher, $raw)) {
            throw new Exception('Error: Invalid key or unsupported cipher.');
        }
        $this->setKey($key, $raw);
        $this->setCipher($cipher);
    }

    /**
     * Set cipher
     *
     * @param  string $cipher
     * @return static
     */
    public function setCipher(string $cipher): static
    {
        $this->cipher = strtolower($cipher);
        return $this;
    }

    /**
     * Get cipher
     *
     * @return string
     */
    public function getCipher(): string
    {
        return $this->cipher;
    }

    /**
     * Has cipher
     *
     * @return bool
     */
    public function hasCipher(): bool
    {
        return !empty($this->cipher);
    }

    /**
     * Set key
     *
     * @param  string $key
     * @param  bool   $raw
     * @return static
     */
    public function setKey(string $key, bool $raw = true): static
    {
        $this->key = ($raw) ? $key : base64_decode($key);
        return $this;
    }

    /**
     * Get key
     *
     * @param  bool $raw
     * @return string
     */
    public function getKey(bool $raw = false): string
    {
        return ($raw) ? $this->key : base64_encode($this->key);
    }

    /**
     * Has key
     *
     * @return bool
     */
    public function hasKey(): bool
    {
        return !empty($this->key);
    }

    /**
     * Get all keys
     *
     * @return array
     */
    public function getAllKeys(): array
    {
        return [$this->key, ...$this->previousKeys];
    }

    /**
     * Set previous keys
     *
     * @param  array $previousKeys
     * @throws Exception
     * @return static
     */
    public function setPreviousKeys(array $previousKeys): static
    {
        if (!empty($this->cipher)) {
            foreach ($previousKeys as $previousKey) {
                if (!static::isValid($previousKey, $this->cipher)) {
                    throw new Exception('Error: Invalid key or unsupported cipher.');
                }
            }
        }

        $this->previousKeys = $previousKeys;

        return $this;
    }

    /**
     * Get previous keys
     *
     * @return array
     */
    public function getPreviousKeys(): array
    {
        return $this->previousKeys;
    }

    /**
     * Has previous keys
     *
     * @return bool
     */
    public function hasPreviousKeys(): bool
    {
        return !empty($this->previousKeys);
    }

    /**
     * Determine if the cipher is available
     *
     * @param  string $cipher
     * @return bool
     */
    abstract public static function isAvailable(string $cipher);

    /**
     * Determine if the key and cipher combination is valid
     *
     * @param  string $key
     * @param  string $cipher
     * @param  bool   $raw
     * @return bool
     */
    abstract public static function isValid(string $key, string $cipher, bool $raw = true): bool;

    /**
     * Encrypt value
     *
     * @param  mixed $value
     * @return string
     */
    abstract public function encrypt(#[\SensitiveParameter] mixed $value): string;

    /**
     * Decrypt value
     *
     * @param  string $payload
     * @return mixed
     */
    abstract public function decrypt(string $payload): mixed;

}
