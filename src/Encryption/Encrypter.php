<?php
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
 * Pop Crypt encrypter
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2027 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
 */
class Encrypter extends AbstractEncrypter
{

    /**
     * Cipher constants
     */
    const AES_128_CBC = 'aes-128-cbc';
    const AES_256_CBC = 'aes-256-cbc';
    const AES_128_GCM = 'aes-128-gcm';
    const AES_256_GCM = 'aes-256-gcm';

    /**
     * Available ciphers
     *
     * @var array
     */
    private static $ciphers = [
        'aes-128-cbc' => ['size' => 16, 'aead' => false],
        'aes-256-cbc' => ['size' => 32, 'aead' => false],
        'aes-128-gcm' => ['size' => 16, 'aead' => true],
        'aes-256-gcm' => ['size' => 32, 'aead' => true],
    ];

    /**
     * HKDF info string for the derived AES subkey
     */
    private const HKDF_ENCRYPTION_INFO = 'pop-crypt|encryption-key';

    /**
     * HKDF info string for the derived HMAC subkey
     */
    private const HKDF_MAC_INFO = 'pop-crypt|mac-key';

    /**
     * Create encrypter object
     *
     * @param  string $cipher
     * @param  bool   $raw
     * @return static
     */
    public static function create(string $cipher = 'aes-256-cbc', bool $raw = true): static
    {
        return new static(static::generateKey($cipher), $cipher, $raw);
    }

    /**
     * Load encrypter object from $_ENV
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
        $cipher       = null;
        $key          = null;
        $previousKeys = null;

        if (!empty($_ENV['APP_CIPHER_METHOD'])) {
            $cipher = trim($_ENV['APP_CIPHER_METHOD']);
        }
        if (empty($key) && !empty($_ENV['APP_KEY'])) {
            $key = trim($_ENV['APP_KEY']);
        }
        if (!empty($_ENV['APP_PREVIOUS_KEYS'])) {
            $previousKeys = array_map('trim', explode(',', $_ENV['APP_PREVIOUS_KEYS']));
        }

        if (empty($cipher) || empty($key)) {
            throw new Exception('Error: The encryption properties could not be loaded.');
        }

        $encrypter = new static($key, $cipher, $raw);

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
        return isset(static::$ciphers[strtolower($cipher)]);
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
        $cipher = strtolower($cipher);
        if (!isset(static::$ciphers[$cipher])) {
            return false;
        }
        if (!$raw) {
            $key = base64_decode($key);
        }
        return (mb_strlen($key, '8bit') === static::$ciphers[$cipher]['size']);
    }

    /**
     * Generate encryption key
     *
     * @param  string $cipher
     * @param  bool   $raw
     * @return string
     */
    public static function generateKey(string $cipher, bool $raw = true): string
    {
        $key = random_bytes((static::$ciphers[strtolower($cipher)]['size'] ?? 32));
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
        $aead   = static::$ciphers[$this->cipher]['aead'];
        $iv     = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)));
        $tag    = '';
        $encKey = ($aead) ? $this->key : hash_hkdf('sha256', $this->key, 32, static::HKDF_ENCRYPTION_INFO);
        $value  = openssl_encrypt($value, $this->cipher, $encKey, 0, $iv, $tag);
        $iv     = base64_encode($iv);
        $tag    = base64_encode(($tag ?? ''));
        $mac    = (!$aead) ?
            hash_hmac('sha256', $iv . $value, hash_hkdf('sha256', $this->key, 32, static::HKDF_MAC_INFO)) : '';

        $json = json_encode([
            'iv'    => $iv,
            'value' => $value,
            'mac'   => $mac,
            'tag'   => $tag,
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

        $aead = static::$ciphers[$this->cipher]['aead'];

        // Validate that iv and value are strings (prevent TypeError from base64_decode)
        if (!is_string($payload['iv']) || !is_string($payload['value'])) {
            throw new Exception('Error: The payload is not valid data.');
        }

        // Non-AEAD (CBC) ciphers require a string 'mac'; AEAD ciphers don't use one.
        if (!$aead && (!isset($payload['mac']) || !is_string($payload['mac']))) {
            throw new Exception('Error: The payload is not valid data.');
        }

        // 'tag' is optional, but if present it must be a string (prevent TypeError from base64_decode)
        if (isset($payload['tag']) && !is_string($payload['tag'])) {
            throw new Exception('Error: The payload is not valid data.');
        }

        $iv        = base64_decode($payload['iv']);
        $tag       = (!empty($payload['tag'])) ? base64_decode($payload['tag']) : '';
        $decrypted = false;
        $validMac  = null;

        foreach ($this->getAllKeys() as $key) {
            $encKey = ($aead) ? $key : hash_hkdf('sha256', $key, 32, static::HKDF_ENCRYPTION_INFO);

            if (!$aead) {
                $macKey   = hash_hkdf('sha256', $key, 32, static::HKDF_MAC_INFO);
                $validMac = hash_equals(hash_hmac('sha256', $payload['iv'] . $payload['value'], $macKey), $payload['mac']);
                if (!$validMac) {
                    continue;
                }
            }

            $decrypted = openssl_decrypt($payload['value'], $this->cipher, $encKey, 0, $iv, $tag);

            if ($decrypted !== false) {
                break;
            }
        }

        if ($validMac === false) {
            throw new Exception('Error: Invalid MAC value.');
        }
        if ($decrypted === false) {
            throw new Exception('Error: Unable to decrypt the data.');
        }

        return $decrypted;
    }

}
