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
 * Pop Crypt hasher factory
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <dev@noladev.com>
 * @copyright  Copyright (c) 2009-2026 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    3.0.0
 */
class Hasher
{

    /**
     * Create hasher object with options
     *
     * @param  mixed $algorithm
     * @throws \InvalidArgumentException
     * @return AbstractHasher
     */
    public static function create(mixed $algorithm, array $options = []): AbstractHasher
    {
        if (!in_array($algorithm, [PASSWORD_BCRYPT, PASSWORD_ARGON2I, PASSWORD_ARGON2ID])) {
            throw new Exception('Error: Invalid hashing algorithm.');
        }

        switch ($algorithm) {
            case PASSWORD_BCRYPT:
                $hasher = new BcryptHasher();
                break;
            case PASSWORD_ARGON2I:
                $hasher = new Argon2IHasher();
                break;
            case PASSWORD_ARGON2ID:
                $hasher = new Argon2IdHasher();
                break;
        }

        if (!empty($options)) {
            $hasher->setOptions($options);
        }

        return $hasher;
    }
}
