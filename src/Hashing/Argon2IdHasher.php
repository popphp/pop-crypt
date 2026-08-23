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
namespace Pop\Crypt\Hashing;

/**
 * Pop Crypt Argon2ID hasher
 *
 * @category   Pop
 * @package    Pop\Crypt
 * @author     Nick Sagona, III <nick@popphp.org>
 * @copyright  Copyright (c) 2009-2027 NOLA Interactive, LLC.
 * @license    https://www.popphp.org/license     New BSD License
 * @version    4.0.0
 */
class Argon2IdHasher extends AbstractArgon2Hasher
{

    /**
     * Make hashed value (based on the hasher class)
     *
     * @param  string $value
     * @return string
     */
    public function make(#[\SensitiveParameter] string $value): string
    {
        $options = [
            'memory_cost' => $this->getMemoryCost(),
            'time_cost'   => $this->getTimeCost(),
            'threads'     => $this->getThreads(),
        ];
        return $this->createHash($value, PASSWORD_ARGON2ID, $options);
    }

    /**
     * Determine if the hashed value requires re-hashing (based on the hasher class)
     *
     * @param  string $hashedValue
     * @return bool
     */
    public function requiresRehash(string $hashedValue): bool
    {
        $options = [
            'memory_cost' => $this->getMemoryCost(),
            'time_cost'   => $this->getTimeCost(),
            'threads'     => $this->getThreads(),
        ];
        return $this->needsRehash($hashedValue, PASSWORD_ARGON2ID, $options);
    }

}
