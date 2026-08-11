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

    public function testDecryptDoesNotSkipValidPreviousKeyOnCoincidentalPadding()
    {
        $realEncrypter = Encryption\Encrypter::create('aes-256-cbc');
        $realKey       = $realEncrypter->getKey(true);
        $encrypted     = $realEncrypter->encrypt('secret payload');

        $payload     = json_decode(base64_decode($encrypted), true);
        $iv          = base64_decode($payload['iv']);
        $cipherValue = $payload['value'];

        // Find a "decoy" key that, purely by chance, produces syntactically valid
        // (non-false) CBC/PKCS7 decryption of this ciphertext but is not the real
        // key (so its MAC will never match). This reproduces the scenario where
        // decrypt() must not stop trying keys just because openssl_decrypt()
        // returned something.
        $decoyKey = null;
        for ($i = 0; $i < 20000; $i++) {
            $candidate = random_bytes(32);
            if (openssl_decrypt($cipherValue, 'aes-256-cbc', $candidate, 0, $iv) !== false) {
                $decoyKey = $candidate;
                break;
            }
        }
        $this->assertNotNull($decoyKey, 'Could not find a decoy key with coincidentally valid padding.');

        $rotatedEncrypter = new Encryption\Encrypter($decoyKey, 'aes-256-cbc');
        $rotatedEncrypter->setPreviousKeys([$realKey]);

        $decrypted = $rotatedEncrypter->decrypt($encrypted);
        $this->assertEquals('secret payload', $decrypted);
    }

    public function testSetCipherWithInvalidCipherThrowsException()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create();
        $encrypter->setCipher('aes-256-bad');
    }

    public function testSetCipherIncompatibleWithExistingKeyThrowsException()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create('aes-256-cbc');
        $encrypter->setCipher('aes-128-cbc');
    }

    public function testSetKeyWithWrongSizeForCipherThrowsException()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        $encrypter = Encryption\Encrypter::create('aes-256-cbc');
        $encrypter->setKey(random_bytes(16));
    }

    public function testEncryptRejectsNonStringValue()
    {
        $this->expectException(\TypeError::class);
        $encrypter = Encryption\Encrypter::create();
        $encrypter->encrypt(['not' => 'a string']);
    }

    public function testLoadDefaultsToBase64EncodedEnvKey()
    {
        $cipher = 'aes-256-cbc';
        $key    = Encryption\Encrypter::generateKey($cipher, false);

        $_ENV['APP_CIPHER_METHOD'] = $cipher;
        $_ENV['APP_KEY']           = $key;

        try {
            $encrypter = Encryption\Encrypter::load();
            $encrypted = $encrypter->encrypt('load test');
            $this->assertEquals('load test', $encrypter->decrypt($encrypted));
            $this->assertEquals($cipher, $encrypter->getCipher());
        } finally {
            unset($_ENV['APP_CIPHER_METHOD'], $_ENV['APP_KEY']);
        }
    }

    public function testLoadWithPreviousKeysFromEnv()
    {
        $cipher    = 'aes-256-cbc';
        $oldKey    = Encryption\Encrypter::generateKey($cipher, false);
        $oldEnc    = new Encryption\Encrypter($oldKey, $cipher, false);
        $encrypted = $oldEnc->encrypt('rotated payload');
        $newKey    = Encryption\Encrypter::generateKey($cipher, false);

        $_ENV['APP_CIPHER_METHOD'] = $cipher;
        $_ENV['APP_KEY']           = $newKey;
        $_ENV['APP_PREVIOUS_KEYS'] = $oldKey;

        try {
            $encrypter = Encryption\Encrypter::load();
            $this->assertTrue($encrypter->hasPreviousKeys());
            $this->assertEquals('rotated payload', $encrypter->decrypt($encrypted));
        } finally {
            unset($_ENV['APP_CIPHER_METHOD'], $_ENV['APP_KEY'], $_ENV['APP_PREVIOUS_KEYS']);
        }
    }

    public function testLoadThrowsExceptionWhenEnvIsMissing()
    {
        unset($_ENV['APP_CIPHER_METHOD'], $_ENV['APP_KEY'], $_ENV['APP_PREVIOUS_KEYS']);
        $this->expectException('Pop\Crypt\Encryption\Exception');
        Encryption\Encrypter::load();
    }

    public function testCbcMacIsNotComputedWithRawMasterKey()
    {
        $encrypter = Encryption\Encrypter::create('aes-256-cbc');
        $rawKey    = $encrypter->getKey(true);
        $encrypted = $encrypter->encrypt('password');

        $payload   = json_decode(base64_decode($encrypted), true);
        $rawKeyMac = hash_hmac('sha256', $payload['iv'] . $payload['value'], $rawKey);

        $this->assertNotEquals($rawKeyMac, $payload['mac']);
    }

    public function testEncrypterImplementsEncrypterInterface()
    {
        $encrypter = Encryption\Encrypter::create();
        $this->assertInstanceOf(Encryption\EncrypterInterface::class, $encrypter);
    }

    public function testDecryptThrowsExceptionForNonStringIv()
    {
        $this->expectException(Encryption\Exception::class);
        $encrypter = Encryption\Encrypter::create();
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        $enc['iv'] = ['a'];
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

    public function testDecryptThrowsExceptionForNonStringValue()
    {
        $this->expectException(Encryption\Exception::class);
        $encrypter = Encryption\Encrypter::create();
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        $enc['value'] = ['x'];
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

    public function testDecryptThrowsExceptionForMissingMac()
    {
        $this->expectException(Encryption\Exception::class);
        $encrypter = Encryption\Encrypter::create('aes-256-cbc');
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        unset($enc['mac']);
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

    public function testDecryptThrowsExceptionForNonStringMac()
    {
        $this->expectException(Encryption\Exception::class);
        $encrypter = Encryption\Encrypter::create('aes-256-cbc');
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        $enc['mac'] = ['q'];
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

    public function testDecryptThrowsExceptionForNonStringTag()
    {
        $this->expectException(Encryption\Exception::class);
        $encrypter = Encryption\Encrypter::create('aes-256-gcm');
        $encrypted = $encrypter->encrypt('password');

        $enc = json_decode(base64_decode($encrypted), true);
        $enc['tag'] = ['z'];
        $decrypted = $encrypter->decrypt(base64_encode(json_encode($enc)));
    }

    public function testEncryptDecryptRoundTripForAllCiphers()
    {
        $ciphers = [
            Encryption\Encrypter::AES_128_CBC,
            Encryption\Encrypter::AES_256_CBC,
            Encryption\Encrypter::AES_128_GCM,
            Encryption\Encrypter::AES_256_GCM,
        ];

        foreach ($ciphers as $cipher) {
            $encrypter = Encryption\Encrypter::create($cipher);
            $encrypted = $encrypter->encrypt('password');
            $decrypted = $encrypter->decrypt($encrypted);
            $this->assertEquals('password', $decrypted, "Round trip failed for cipher {$cipher}");
        }
    }

}
