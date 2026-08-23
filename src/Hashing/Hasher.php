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
namespace Pop\Crypt\Hashing;

/**
 * Pop Crypt hasher factory
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2026 Nick Sagona, III
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
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
        $hasher = match ($algorithm) {
            PASSWORD_BCRYPT   => new BcryptHasher(),
            PASSWORD_ARGON2I  => new Argon2IHasher(),
            PASSWORD_ARGON2ID => new Argon2IdHasher(),
            default           => throw new Exception('Error: Invalid hashing algorithm.'),
        };

        if (!empty($options)) {
            $hasher->setOptions($options);
        }

        return $hasher;
    }
}
