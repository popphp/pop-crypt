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
        "popphp/pop-crypt" : "^3.0.0"
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

[Top](#pop-crypt)

Encryption
----------

The Encryption classes are built using the `openssl` extensions and its related functions. Supported ciphers are:

- `aes-128-cbc`
- `aes-256-cbc`
- `aes-128-gcm`
- `aes-256-gcm`

It is important to safely store the key or keys used to generate the encrypted data. When correctly paired with
their cipher, the encrypted data can successfully be decrypted. However, if the key is incorrect or matched with
the wrong cipher, decryption will fail

### Generate Key

A key that matches the chosen cipher can be generated with the following method:

```php
use Pop\Crypt\Encryption;

$key = Encryption\Encrypter::generateKey($cipher, false);
```

##### Raw vs Base-64

Methods the manage the key values have an optional `$raw` parameter.

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

[Top](#pop-crypt)
