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
     * Encrypt value
     *
     * @param  mixed $value
     * @return mixed
     */
    public function encrypt(mixed $value): mixed;

    /**
     * Decrypt value
     *
     * @param  mixed $value
     * @return mixed
     */
    public function decrypt(mixed $value): mixed;

}
