<?php

namespace Pop\Crypt\Test;

use PHPUnit\Framework\TestCase;
use Pop\Crypt\Encryption;

class EncrypterTest extends TestCase
{

    public function testEncryption()
    {
        $encrypter = Encryption\Encrypter::create();
        $encrypted = $encrypter->encrypt('password');
        $decrypted = $encrypter->decrypt($encrypted);
        $this->assertEquals('password', $decrypted);
        $this->assertTrue(Encryption\Encrypter::isAvailable('aes-256-cbc'));
        $this->assertFalse(Encryption\Encrypter::isAvailable('aes-256-bad'));
        $this->assertTrue($encrypter->hasKey());
        $this->assertTrue($encrypter->hasCipher());
        $this->assertEquals('aes-256-cbc', $encrypter->getCipher());
    }

    public function testIsValid()
    {
        $encrypter = Encryption\Encrypter::create();
        $key       = $encrypter->getKey();
        $this->assertTrue(Encryption\Encrypter::isValid($key, 'aes-256-cbc', false));
        $this->assertFalse(Encryption\Encrypter::isValid($key, 'aes-128-cbc', false));
        $this->assertFalse(Encryption\Encrypter::isValid($key, 'aes-256-bad', false));
    }

    public function testPreviousKeys1()
    {
        $encrypter = Encryption\Encrypter::create();
        $origKey   = $encrypter->getKey(true);
        $newKey    = $encrypter->generateKey('aes-256-cbc');

        $newEncrypter = new Encryption\Encrypter($newKey, 'aes-256-cbc');
        $newEncrypter->setPreviousKeys([$origKey]);
        $previousKeys1 = $newEncrypter->getPreviousKeys();
        $previousKeys2 = $newEncrypter->getPreviousKeys(true);
        $this->assertIsArray($previousKeys1);
        $this->assertCount(1, $previousKeys2);
    }

    public function testPreviousKeys2()
    {
        $encrypter = Encryption\Encrypter::create();
        $origKey   = $encrypter->getKey();
        $newKey    = $encrypter->generateKey('aes-256-cbc');

        $newEncrypter = new Encryption\Encrypter($newKey, 'aes-256-cbc');
        $newEncrypter->setPreviousKeys([$origKey], false);
        $this->assertTrue($newEncrypter->hasPreviousKeys());
        $previousKeys1 = $newEncrypter->getPreviousKeys();
        $previousKeys2 = $newEncrypter->getPreviousKeys(true);
        $this->assertIsArray($previousKeys1);
        $this->assertCount(1, $previousKeys2);
    }

    public function testPreviousKeysException()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create();
        $origKey   = $encrypter->getKey();
        $newKey    = $encrypter->generateKey('aes-256-cbc');

        $newEncrypter = new Encryption\Encrypter($newKey, 'aes-256-cbc');
        $newEncrypter->setPreviousKeys(['bad_key'], false);
    }

    public function testEncryptException()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create('aes-256-bad');
    }

    public function testDecryptException1()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create();
        $encrypted = $encrypter->encrypt('password');
        $decrypted = $encrypter->decrypt(json_encode('[]'));
    }

    public function testDecryptException2()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create();
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        $enc['mac'] = 'bad_mac';
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

    public function testDecryptException3()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create('aes-256-gcm');
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        $enc['value'] = 'bad_value';
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

}
