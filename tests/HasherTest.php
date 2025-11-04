<?php

namespace Pop\Crypt\Test;

use PHPUnit\Framework\TestCase;
use Pop\Crypt\Hashing;

class HasherTest extends TestCase
{

    public function testBcrypt()
    {
        $hasher = Hashing\BcryptHasher::create(['cost' => 14]);
        $hash   = $hasher->make('password');
        $this->assertTrue($hasher->verify('password', $hash));
        $this->assertFalse($hasher->verify('bad', $hash));
        $this->assertFalse($hasher->requiresRehash($hash));
        $this->assertIsArray($hasher->getAlgorithms());
        $this->assertIsArray($hasher->getInfo($hash));
        $this->assertTrue($hasher->hasCost());
        $this->assertEquals(14, $hasher->getCost());
    }

    public function testArgon2I()
    {
        $hasher = Hashing\Argon2IHasher::create([
            'memory_cost' => 131072,
            'time_cost'   => 6,
            'threads'     => 2,
        ]);
        $hash   = $hasher->make('password');
        $this->assertTrue($hasher->verify('password', $hash));
        $this->assertFalse($hasher->verify('bad', $hash));
        $this->assertFalse($hasher->requiresRehash($hash));
        $this->assertIsArray($hasher->getAlgorithms());
        $this->assertIsArray($hasher->getInfo($hash));
        $this->assertTrue($hasher->hasMemoryCost());
        $this->assertEquals(131072, $hasher->getMemoryCost());
        $this->assertTrue($hasher->hasTimeCost());
        $this->assertEquals(6, $hasher->getTimeCost());
        $this->assertTrue($hasher->hasThreads());
        $this->assertEquals(2, $hasher->getThreads());
    }

    public function testArgon2Id()
    {
        $hasher = Hashing\Argon2IdHasher::create([
            'memory_cost' => 131072,
            'time_cost'   => 6,
            'threads'     => 2,
        ]);
        $hash   = $hasher->make('password');
        $this->assertTrue($hasher->verify('password', $hash));
        $this->assertFalse($hasher->verify('bad', $hash));
        $this->assertTrue($hasher->requiresRehash($hash));
        $this->assertIsArray($hasher->getAlgorithms());
        $this->assertIsArray($hasher->getInfo($hash));
        $this->assertTrue($hasher->hasMemoryCost());
        $this->assertEquals(131072, $hasher->getMemoryCost());
        $this->assertTrue($hasher->hasTimeCost());
        $this->assertEquals(6, $hasher->getTimeCost());
        $this->assertTrue($hasher->hasThreads());
        $this->assertEquals(2, $hasher->getThreads());
    }

    public function testFactory()
    {
        $bcryptHasher   = Hashing\Hasher::create(PASSWORD_BCRYPT, ['cost' => 14]);
        $argon2IHasher  = Hashing\Hasher::create(PASSWORD_ARGON2I, ['time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST]);
        $argon2IdHasher = Hashing\Hasher::create(PASSWORD_ARGON2ID, ['time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST]);

        $this->assertInstanceOf(Hashing\BcryptHasher::class, $bcryptHasher);
        $this->assertInstanceOf(Hashing\Argon2IHasher::class, $argon2IHasher);
        $this->assertInstanceOf(Hashing\Argon2IdHasher::class, $argon2IdHasher);
    }

    public function testFactoryException()
    {
        $this->expectException('Pop\Crypt\Hashing\Exception');
        $hasher = Hashing\Hasher::create('bad_algo');
    }

}
