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
 * Pop Crypt encrypter
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
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
     * Create encrypter object
     *
     * @param  string $cipher
     * @return static
     */
    public static function create(string $cipher = 'aes-256-cbc'): static
    {
        return new static(static::generateKey($cipher), $cipher);
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
     * @param  mixed $value
     * @return string
     */
    public function encrypt(#[\SensitiveParameter] mixed $value): string
    {
        $iv    = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)));
        $tag   = '';
        $value = openssl_encrypt($value, $this->cipher, $this->key, 0, $iv, $tag);
        $iv    = base64_encode($iv);
        $tag   = base64_encode(($tag ?? ''));
        $mac   = (!static::$ciphers[$this->cipher]['aead']) ?
            hash_hmac('sha256', $iv . $value, $this->key) : '';

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
     * @return mixed
     */
    public function decrypt(string $payload): mixed
    {
        $payload = json_decode(base64_decode($payload), true);

        if (!is_array($payload) || (!isset($payload['iv']) || !isset($payload['value']))) {
            throw new Exception('Error: The payload is not valid data.');
        }

        $iv        = base64_decode($payload['iv']);
        $tag       = (!empty($payload['tag'])) ? base64_decode($payload['tag']) : '';
        $decrypted = false;
        $validMac  = null;

        foreach ($this->getAllKeys() as $key) {
            $decrypted = openssl_decrypt($payload['value'], $this->cipher, $key, 0, $iv, $tag);

            if (!static::$ciphers[$this->cipher]['aead']) {
                $validMac = hash_equals(hash_hmac('sha256', $payload['iv'] . $payload['value'], $key), $payload['mac']);
            }

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
