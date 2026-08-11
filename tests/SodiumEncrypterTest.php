<?php

namespace Pop\Crypt\Test;

use PHPUnit\Framework\TestCase;
use Pop\Crypt\Encryption;

class SodiumEncrypterTest extends TestCase
{

    public function testConstructWithValidRawKey()
    {
        $key       = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $encrypter = new Encryption\SodiumEncrypter($key);

        $this->assertTrue($encrypter->hasKey());
        $this->assertTrue($encrypter->hasCipher());
        $this->assertEquals('xchacha20-poly1305', $encrypter->getCipher());
        $this->assertInstanceOf(Encryption\EncrypterInterface::class, $encrypter);
    }

    public function testConstructWithWrongSizeKeyThrowsException()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');
        new Encryption\SodiumEncrypter(random_bytes(16));
    }

    public function testIsAvailable()
    {
        $this->assertTrue(Encryption\SodiumEncrypter::isAvailable('xchacha20-poly1305'));
        $this->assertFalse(Encryption\SodiumEncrypter::isAvailable('aes-256-cbc'));
    }

    public function testIsValid()
    {
        $key = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $this->assertTrue(Encryption\SodiumEncrypter::isValid($key, 'xchacha20-poly1305'));
        $this->assertFalse(Encryption\SodiumEncrypter::isValid(random_bytes(16), 'xchacha20-poly1305'));
        $this->assertFalse(Encryption\SodiumEncrypter::isValid($key, 'aes-256-cbc'));
    }

    public function testGenerateKey()
    {
        $rawKey    = Encryption\SodiumEncrypter::generateKey();
        $base64Key = Encryption\SodiumEncrypter::generateKey(false);

        $this->assertEquals(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, mb_strlen($rawKey, '8bit'));
        $this->assertTrue(Encryption\SodiumEncrypter::isValid($base64Key, 'xchacha20-poly1305', false));
    }

    public function testEncryptAndDecryptRoundTrip()
    {
        $key       = Encryption\SodiumEncrypter::generateKey();
        $encrypter = new Encryption\SodiumEncrypter($key);
        $encrypted = $encrypter->encrypt('sensitive data');

        $this->assertNotEquals('sensitive data', $encrypted);
        $this->assertEquals('sensitive data', $encrypter->decrypt($encrypted));
    }

    public function testDecryptThrowsExceptionOnTamperedValue()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');

        $key       = Encryption\SodiumEncrypter::generateKey();
        $encrypter = new Encryption\SodiumEncrypter($key);
        $encrypted = $encrypter->encrypt('sensitive data');

        $payload          = json_decode(base64_decode($encrypted), true);
        $payload['value'] = base64_encode(base64_decode($payload['value']) . 'x');

        $encrypter->decrypt(base64_encode(json_encode($payload)));
    }

    public function testDecryptThrowsExceptionOnMalformedPayload()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');

        $key       = Encryption\SodiumEncrypter::generateKey();
        $encrypter = new Encryption\SodiumEncrypter($key);
        $encrypter->decrypt(base64_encode(json_encode(['nope' => true])));
    }

    public function testDecryptSucceedsWithRotatedPreviousKey()
    {
        $oldKey    = Encryption\SodiumEncrypter::generateKey();
        $oldEnc    = new Encryption\SodiumEncrypter($oldKey);
        $encrypted = $oldEnc->encrypt('rotated payload');

        $newKey       = Encryption\SodiumEncrypter::generateKey();
        $newEncrypter = new Encryption\SodiumEncrypter($newKey);
        $newEncrypter->setPreviousKeys([$oldKey]);

        $this->assertEquals('rotated payload', $newEncrypter->decrypt($encrypted));
    }

    public function testDecryptThrowsExceptionWhenNoKeyMatches()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');

        $oldKey    = Encryption\SodiumEncrypter::generateKey();
        $oldEnc    = new Encryption\SodiumEncrypter($oldKey);
        $encrypted = $oldEnc->encrypt('rotated payload');

        $wrongKey = Encryption\SodiumEncrypter::generateKey();
        $wrongEnc = new Encryption\SodiumEncrypter($wrongKey);
        $wrongEnc->decrypt($encrypted);
    }

    public function testCreate()
    {
        $encrypter = Encryption\SodiumEncrypter::create();
        $encrypted = $encrypter->encrypt('created value');

        $this->assertEquals('created value', $encrypter->decrypt($encrypted));
        $this->assertEquals('xchacha20-poly1305', $encrypter->getCipher());
    }

    public function testLoadDefaultsToBase64EncodedEnvKey()
    {
        $key = Encryption\SodiumEncrypter::generateKey(false);

        $_ENV['APP_KEY'] = $key;

        try {
            $encrypter = Encryption\SodiumEncrypter::load();
            $encrypted = $encrypter->encrypt('load test');
            $this->assertEquals('load test', $encrypter->decrypt($encrypted));
        } finally {
            unset($_ENV['APP_KEY']);
        }
    }

    public function testLoadWithPreviousKeysFromEnv()
    {
        $oldKey    = Encryption\SodiumEncrypter::generateKey(false);
        $oldEnc    = new Encryption\SodiumEncrypter($oldKey, false);
        $encrypted = $oldEnc->encrypt('rotated payload');
        $newKey    = Encryption\SodiumEncrypter::generateKey(false);

        $_ENV['APP_KEY']           = $newKey;
        $_ENV['APP_PREVIOUS_KEYS'] = $oldKey;

        try {
            $encrypter = Encryption\SodiumEncrypter::load();
            $this->assertTrue($encrypter->hasPreviousKeys());
            $this->assertEquals('rotated payload', $encrypter->decrypt($encrypted));
        } finally {
            unset($_ENV['APP_KEY'], $_ENV['APP_PREVIOUS_KEYS']);
        }
    }

    public function testLoadThrowsExceptionWhenEnvIsMissing()
    {
        unset($_ENV['APP_KEY'], $_ENV['APP_PREVIOUS_KEYS']);
        $this->expectException('Pop\Crypt\Encryption\Exception');
        Encryption\SodiumEncrypter::load();
    }

    public function testDecryptThrowsExceptionOnWrongLengthNonce()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');

        $key       = Encryption\SodiumEncrypter::generateKey();
        $encrypter = new Encryption\SodiumEncrypter($key);
        $encrypted = $encrypter->encrypt('sensitive data');

        $payload       = json_decode(base64_decode($encrypted), true);
        $nonce         = base64_decode($payload['iv']);
        $payload['iv'] = base64_encode(substr($nonce, 0, -1)); // truncate nonce

        $encrypter->decrypt(base64_encode(json_encode($payload)));
    }

    public function testDecryptThrowsExceptionOnNonStringPayloadValues()
    {
        $this->expectException('Pop\Crypt\Encryption\Exception');

        $key       = Encryption\SodiumEncrypter::generateKey();
        $encrypter = new Encryption\SodiumEncrypter($key);

        // Payload with non-string iv value
        $encrypter->decrypt(base64_encode(json_encode(['iv' => ['not', 'a', 'string'], 'value' => 'test'])));
    }

}
