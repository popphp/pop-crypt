<?php
declare(strict_types=1);
/**
 * Pop PHP Framework (https://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp-framework
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2027 NOLA Interactive, LLC.
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
 * @copyright  Copyright (c) 2009-2027 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
 */
abstract class AbstractEncrypter implements EncrypterInterface
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
        $this->setCipher($cipher);
        $this->setKey($key, $raw);
    }

    /**
     * Set cipher
     *
     * @param  string $cipher
     * @throws Exception
     * @return static
     */
    public function setCipher(string $cipher): static
    {
        $cipher = strtolower($cipher);

        if (!static::isAvailable($cipher)) {
            throw new Exception('Error: Invalid or unsupported cipher.');
        }
        if ($this->hasKey() && !static::isValid($this->key, $cipher)) {
            throw new Exception('Error: Invalid key or unsupported cipher.');
        }

        $this->cipher = $cipher;
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
     * @throws Exception
     * @return static
     */
    public function setKey(string $key, bool $raw = true): static
    {
        $key = ($raw) ? $key : base64_decode($key);

        if (!empty($this->cipher) && !static::isValid($key, $this->cipher)) {
            throw new Exception('Error: Invalid key or unsupported cipher.');
        }

        $this->key = $key;
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
     * @param  bool  $raw
     * @throws Exception
     * @return static
     */
    public function setPreviousKeys(array $previousKeys, bool $raw = true): static
    {
        if (!empty($this->cipher)) {
            foreach ($previousKeys as $i => $previousKey) {
                if (!$raw) {
                    $previousKey = base64_decode($previousKey);
                }
                if (!static::isValid($previousKey, $this->cipher)) {
                    throw new Exception('Error: Invalid key or unsupported cipher.');
                }
                $this->previousKeys[] = $previousKey;
            }
        }

        return $this;
    }

    /**
     * Get previous keys
     *
     * @param  bool $raw
     * @return array
     */
    public function getPreviousKeys(bool $raw = false): array
    {
        if (!$raw) {
            return array_map(function ($value) {
                return base64_encode($value);
            }, $this->previousKeys);
        } else {
            return $this->previousKeys;
        }
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
     * @param  string $value
     * @return string
     */
    abstract public function encrypt(#[\SensitiveParameter] string $value): string;

    /**
     * Decrypt value
     *
     * @param  string $payload
     * @return string
     */
    abstract public function decrypt(string $payload): string;

}
