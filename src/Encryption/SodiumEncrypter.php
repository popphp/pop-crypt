<?php
declare(strict_types=1);
/**
 * Pop PHP Framework (https://www.popphp.org/)
 *
 * @link       https://github.com/popphp/popphp-framework
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2027 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 */

/**
 * @namespace
 */
namespace Pop\Crypt\Encryption;

/**
 * Pop Crypt sodium encrypter
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2027 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
 */
class SodiumEncrypter extends AbstractEncrypter
{

    /**
     * Cipher constant
     */
    const CIPHER = 'xchacha20-poly1305';

    /**
     * Constructor
     *
     * Instantiate the SodiumEncrypter object
     *
     * @param  string $key
     * @param  bool   $raw
     * @throws Exception
     */
    public function __construct(string $key, bool $raw = true)
    {
        parent::__construct($key, static::CIPHER, $raw);
    }

    /**
     * Create sodium encrypter object
     *
     * @param  bool $raw
     * @return static
     */
    public static function create(bool $raw = true): static
    {
        return new static(static::generateKey($raw), $raw);
    }

    /**
     * Load sodium encrypter object from $_ENV
     *
     * Defaults to treating APP_KEY/APP_PREVIOUS_KEYS as base64-encoded strings,
     * since that's the standard way to store binary key material in a .env file.
     *
     * @param  bool $raw
     * @throws Exception
     * @return static
     */
    public static function load(bool $raw = false): static
    {
        $key          = null;
        $previousKeys = null;

        if (!empty($_ENV['APP_KEY'])) {
            $key = trim($_ENV['APP_KEY']);
        }
        if (!empty($_ENV['APP_PREVIOUS_KEYS'])) {
            $previousKeys = array_map('trim', explode(',', $_ENV['APP_PREVIOUS_KEYS']));
        }

        if (empty($key)) {
            throw new Exception('Error: The encryption properties could not be loaded.');
        }

        $encrypter = new static($key, $raw);

        if (!empty($previousKeys)) {
            $encrypter->setPreviousKeys($previousKeys, $raw);
        }

        return $encrypter;
    }

    /**
     * Determine if the cipher is available
     *
     * @param  string $cipher
     * @return bool
     */
    public static function isAvailable(string $cipher): bool
    {
        return (strtolower($cipher) === static::CIPHER) && extension_loaded('sodium');
    }

    /**
     * Determine if the key and cipher combination is valid
     *
     * @param  string $key
     * @param  string $cipher
     * @param  bool   $raw
     * @return bool
     */
    public static function isValid(string $key, string $cipher, bool $raw = true): bool
    {
        if (!static::isAvailable($cipher)) {
            return false;
        }
        if (!$raw) {
            $key = base64_decode($key);
        }
        return (mb_strlen($key, '8bit') === SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    }

    /**
     * Generate encryption key
     *
     * @param  bool $raw
     * @return string
     */
    public static function generateKey(bool $raw = true): string
    {
        $key = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        return ($raw) ? $key : base64_encode($key);
    }

    /**
     * Encrypt value
     *
     * @param  string $value
     * @return string
     */
    public function encrypt(#[\SensitiveParameter] string $value): string
    {
        // The 24-byte XChaCha20 nonce is large enough that a fresh random value
        // per message is safe at any realistic volume (unlike GCM's 96-bit nonce,
        // which has a birthday-bound collision risk at very high encryption
        // volumes under a single key).
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $value = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($value, '', $nonce, $this->key);

        $json = json_encode([
            'iv'    => base64_encode($nonce),
            'value' => base64_encode($value),
        ], JSON_UNESCAPED_SLASHES);

        return base64_encode($json);
    }

    /**
     * Decrypt value
     *
     * @param  string $payload
     * @throws Exception
     * @return string
     */
    public function decrypt(string $payload): string
    {
        $payload = json_decode(base64_decode($payload), true);

        if (!is_array($payload) || (!isset($payload['iv']) || !isset($payload['value']))) {
            throw new Exception('Error: The payload is not valid data.');
        }

        // Validate that iv and value are strings (prevent TypeError from base64_decode)
        if (!is_string($payload['iv']) || !is_string($payload['value'])) {
            throw new Exception('Error: The payload is not valid data.');
        }

        $nonce     = base64_decode($payload['iv']);
        $value     = base64_decode($payload['value']);
        $decrypted = false;

        foreach ($this->getAllKeys() as $key) {
            try {
                $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($value, '', $nonce, $key);
            } catch (\SodiumException $e) {
                // Wrong nonce length or other sodium error - treat as decryption failure
                $decrypted = false;
            }

            if ($decrypted !== false) {
                break;
            }
        }

        if ($decrypted === false) {
            throw new Exception('Error: Unable to decrypt the data.');
        }

        return $decrypted;
    }

}
