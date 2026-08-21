<?php

namespace Pop\Crypt\Test\Signature;

use PHPUnit\Framework\TestCase;
use Pop\Crypt\Exception;
use Pop\Crypt\Signature\Verifier;

class VerifierTest extends TestCase
{

    public function testHmacValidSignatureVerifies()
    {
        $data      = 'header.payload';
        $secret    = 'my-shared-secret';
        $signature = hash_hmac('sha256', $data, $secret, true);

        $this->assertTrue(Verifier::hmac($data, $signature, $secret));
    }

    public function testHmacWrongSecretFails()
    {
        $data      = 'header.payload';
        $signature = hash_hmac('sha256', $data, 'right-secret', true);

        $this->assertFalse(Verifier::hmac($data, $signature, 'wrong-secret'));
    }

    public function testHmacTamperedDataFails()
    {
        $secret    = 'my-shared-secret';
        $signature = hash_hmac('sha256', 'original-data', $secret, true);

        $this->assertFalse(Verifier::hmac('tampered-data', $signature, $secret));
    }

    public function testRsaValidSignatureVerifies()
    {
        [$privateKey, $publicKey] = $this->generateKeyPair('rsa');
        $data = 'header.payload';

        openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $this->assertTrue(Verifier::rsa($data, $signature, $publicKey));
    }

    public function testRsaTamperedDataFails()
    {
        [$privateKey, $publicKey] = $this->generateKeyPair('rsa');
        openssl_sign('original-data', $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $this->assertFalse(Verifier::rsa('tampered-data', $signature, $publicKey));
    }

    public function testRsaMalformedKeyThrows()
    {
        $this->expectException(Exception::class);
        Verifier::rsa('data', 'signature', 'not-a-real-key', 'sha256');
    }

    public function testEcValidSignatureVerifies()
    {
        [$privateKey, $publicKey] = $this->generateKeyPair('ec');
        $data = 'header.payload';

        openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $this->assertTrue(Verifier::ec($data, $signature, $publicKey));
    }

    public function testEcTamperedDataFails()
    {
        [$privateKey, $publicKey] = $this->generateKeyPair('ec');
        openssl_sign('original-data', $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $this->assertFalse(Verifier::ec('tampered-data', $signature, $publicKey));
    }

    public function testEcMalformedKeyThrows()
    {
        $this->expectException(Exception::class);
        Verifier::ec('data', 'signature', 'not-a-real-key', 'sha256');
    }

    private function generateKeyPair(string $type): array
    {
        $config = ($type === 'ec')
            ? ['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]
            : ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];

        $resource = openssl_pkey_new($config);
        openssl_pkey_export($resource, $privateKey);
        $publicKey = openssl_pkey_get_details($resource)['key'];

        return [$privateKey, $publicKey];
    }

}
