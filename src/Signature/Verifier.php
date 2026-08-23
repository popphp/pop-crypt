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
namespace Pop\Crypt\Signature;

use Pop\Crypt\Exception;

/**
 * Pop Crypt signature verifier class
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2026 Nick Sagona, III
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
 */
class Verifier
{

    /**
     * Verify an HMAC signature
     *
     * @param  string $data
     * @param  string $signature
     * @param  string $secret
     * @param  string $algo
     * @return bool
     */
    public static function hmac(string $data, string $signature, string $secret, string $algo = 'sha256'): bool
    {
        $expected = hash_hmac($algo, $data, $secret, true);
        return hash_equals($expected, $signature);
    }

    /**
     * Verify an RSA signature
     *
     * @param  string $data
     * @param  string $signature
     * @param  string $publicKey
     * @param  string $algo
     * @throws Exception
     * @return bool
     */
    public static function rsa(string $data, string $signature, string $publicKey, string $algo = 'sha256'): bool
    {
        return self::verify($data, $signature, $publicKey, $algo);
    }

    /**
     * Verify an EC (ECDSA) signature
     *
     * @param  string $data
     * @param  string $signature
     * @param  string $publicKey
     * @param  string $algo
     * @throws Exception
     * @return bool
     */
    public static function ec(string $data, string $signature, string $publicKey, string $algo = 'sha256'): bool
    {
        return self::verify($data, $signature, $publicKey, $algo);
    }

    /**
     * Run openssl_verify() and translate its tri-state (1/0/-1) result
     *
     * @param  string $data
     * @param  string $signature
     * @param  string $publicKey
     * @param  string $algo
     * @throws Exception
     * @return bool
     */
    protected static function verify(string $data, string $signature, string $publicKey, string $algo): bool
    {
        $result = @openssl_verify($data, $signature, $publicKey, $algo);

        if ($result === false || $result === -1) {
            throw new Exception(
                'Unable to verify the signature: ' . (openssl_error_string() ?: 'invalid key or algorithm')
            );
        }

        return ($result === 1);
    }

}
