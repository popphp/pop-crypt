pop-crypt
=========

[![Build Status](https://github.com/popphp/pop-crypt/workflows/phpunit/badge.svg)](https://github.com/popphp/pop-crypt/actions)
[![Coverage Status](http://cc.popphp.org/coverage.php?comp=pop-crypt)](http://cc.popphp.org/pop-crypt/)

[![Join the chat at https://discord.gg/TZjgT74U7E](https://media.popphp.org/img/discord.svg)](https://discord.gg/TZjgT74U7E)

* [Overview](#overview)
* [Install](#install)
* [Quickstart](#quickstart)
* [Hashing](#hashing)
* [Encryption](#encryption)

Overview
--------
`pop-crypt` provides various interfaces to assist in encrypting and decrypting secure hashes
or creating and verifying one-way password hashes.

`pop-crypt` is a component of the [Pop PHP Framework](http://www.popphp.org/).

Install
-------

Install `pop-crypt` using Composer.

    composer require popphp/pop-crypt

Or, require it in your composer.json file

    "require": {
        "popphp/pop-crypt" : "^4.0.0"
    }

[Top](#pop-crypt)

Quickstart
----------

Create a password hash:

```php
use Pop\Crypt\Hashing;

$hasher      = Hashing\BcryptHasher::create();
$hashedValue = $hasher->make('password');

if ($hasher->verify('password', $hashedValue)) {
    echo 'You shall pass!' . PHP_EOL;
} else {
    echo 'YOU SHALL NOT PASS!' . PHP_EOL;
}
```

Create an encrypted value:

```php
use Pop\Crypt\Encryption;

$encrypter = new Encryption\Encrypter($mySecureKey, 'aes-256-cbc');
// Returns a base-64 encoded string of the encrypted data
$encryptedData = $encrypter->encrypt('SENSITIVE_DATA');

// Returns the valid, decrypted data
try {
    $decryptedData = $encrypter->decrypt($encryptedData);
// Else, throws an error exception is something is incorrect or invalid
} catch (\Exception $e) {
    echo $e->getMessage(); 
}
```

[Top](#pop-crypt)

Hashing
-------

The standard PHP password hashing algorithms are supported:

- `PASSWORD_BCRYPT`
- `PASSWORD_ARGON2I`
- `PASSWORD_ARGON2ID`

The `PASSWORD_BCRYPT` algorithm supports the `cost` option. The `salt` has been deprecated as of PHP 8.0.0.

The `PASSWORD_ARGON2I` and `PASSWORD_ARGON2ID` algorithms support the following options:

- `memory_cost`
- `time_cost`
- `threads`

All the algorithms use the standard default values for the options if none are passed.

### Hasher Factory

Instead of instantiating a specific hasher class directly, `Hasher::create()` will build the correct one from a
standard `PASSWORD_*` constant:

```php
use Pop\Crypt\Hashing;

$hasher = Hashing\Hasher::create(PASSWORD_ARGON2ID, [
    'memory_cost' => 131072,
    'time_cost'   => 4,
]);
```

An unsupported algorithm throws a `Pop\Crypt\Hashing\Exception`.

### Input Length Limit

To guard against a hashing algorithm being handed an excessively large value (which can be used to drive up
processing cost as a denial-of-service vector), `make()` and `verify()` will throw a `Pop\Crypt\Hashing\Exception`
for any value longer than `AbstractHasher::MAX_VALUE_LENGTH` (4096 bytes).

[Top](#pop-crypt)

Encryption
----------

Two encrypter implementations are available: `Encrypter`, built on the `openssl` extension, and `SodiumEncrypter`,
built on the `sodium` extension. Both extend `AbstractEncrypter` and implement `EncrypterInterface`, so they share
the same key management, key-rotation, and `$raw` (raw bytes vs. base-64) conventions described below — the
sections further down apply to both unless noted otherwise.

It is important to safely store the key or keys used to generate the encrypted data. When correctly paired with
their cipher, the encrypted data can successfully be decrypted. However, if the key is incorrect or matched with
the wrong cipher, decryption will fail. Decryption failures — an invalid payload, a bad key, a tampered value —
always throw a `Pop\Crypt\Encryption\Exception`, so catching that specific type (rather than a generic `\Exception`)
lets you distinguish this library's errors from anything else that might go wrong.

### AES (OpenSSL)

The `Encrypter` class requires the `openssl` extension. Supported ciphers are:

- `aes-128-cbc`
- `aes-256-cbc`
- `aes-128-gcm`
- `aes-256-gcm`

**Note:** For `aes-128-cbc`/`aes-256-cbc`, the encryption key and the HMAC key used internally are derived from
your master key via HKDF (SHA-256), rather than reusing the same raw key for both. This is transparent to callers
— no code changes are needed — but it means ciphertext produced by versions of this library prior to this change
will no longer decrypt successfully. `aes-128-gcm`/`aes-256-gcm` are unaffected.

#### Generate Key

A key that matches the chosen cipher can be generated with the following method:

```php
use Pop\Crypt\Encryption;

$key = Encryption\Encrypter::generateKey($cipher, false);
```

Or, skip generating and constructing separately by using `create()`, which does both at once:

```php
use Pop\Crypt\Encryption;

$encrypter = Encryption\Encrypter::create('aes-256-gcm');
```

#### Load from Environment

`load()` builds an `Encrypter` from `$_ENV`, reading `APP_CIPHER_METHOD`, `APP_KEY`, and (optionally) a
comma-separated `APP_PREVIOUS_KEYS` — the values are treated as base-64-encoded by default, matching how binary
key material is conventionally stored in a `.env` file:

```php
use Pop\Crypt\Encryption;

// APP_CIPHER_METHOD=aes-256-gcm
// APP_KEY=<base64-encoded key>
// APP_PREVIOUS_KEYS=<base64-encoded key>,<base64-encoded key>
$encrypter = Encryption\Encrypter::load();
```

Throws a `Pop\Crypt\Encryption\Exception` if `APP_CIPHER_METHOD` or `APP_KEY` is missing.

### Raw vs Base-64

Methods that manage the key values have an optional `$raw` parameter.

In the case of generating or getting key values from the encrypter, if `$raw` is true, then the key value will be
returned as a raw string of bytes. Otherwise, if `$raw` is false, the key value will be base-64 encoded before it
is returned.

In the case of setting key values or previous key values in the encrypter, if `$raw` is false, then the key values will
be treated was base-64 encoded values and will be decoded as they are stored in the object. If `$raw` is true, the
key values will not be processed or decoded in any way.

### Previous Keys

In order to preserve legacy keys that have been previously used and rotated out of use, you can load those previous
keys to have the encrypter object attempt to use them if the latest key does not work. This provides graceful rotation
of keys.

```php
use Pop\Crypt\Encryption;

$encrypter = new Encryption\Encrypter($currentKey, 'aes-256-cbc');
$encrypter->setPreviousKeys([$oldKey1, $oldKey2, $oldKey3]);
```

### XChaCha20-Poly1305 (libsodium)

As an alternative to the OpenSSL-based `Encrypter`, `SodiumEncrypter` requires the `sodium` extension (bundled
with PHP since 7.2) and provides authenticated encryption via its XChaCha20-Poly1305 implementation. It has the
same key-rotation and previous-keys support as `Encrypter`, but only supports the one cipher, so there's no cipher
argument to pass anywhere in its API:

```php
use Pop\Crypt\Encryption;

$encrypter     = Encryption\SodiumEncrypter::create();
$encryptedData = $encrypter->encrypt('SENSITIVE_DATA');
$decryptedData = $encrypter->decrypt($encryptedData);
```

`generateKey()`, `load()`, and previous-keys support all work the same way as `Encrypter`, minus the cipher
argument:

```php
use Pop\Crypt\Encryption;

$key       = Encryption\SodiumEncrypter::generateKey(false);
$encrypter = new Encryption\SodiumEncrypter($key, false);
$encrypter->setPreviousKeys([$oldKey1, $oldKey2]);

// APP_KEY=<base64-encoded key>
// APP_PREVIOUS_KEYS=<base64-encoded key>,<base64-encoded key>
$encrypter = Encryption\SodiumEncrypter::load();
```

[Top](#pop-crypt)
