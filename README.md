pop-crypt
=========

END OF LIFE
-----------
The `pop-crypt` component v2.1.1 is now end-of-life and will no longer be maintained.

[![Build Status](https://travis-ci.org/popphp/pop-crypt.svg?branch=master)](https://travis-ci.org/popphp/pop-crypt)
[![Coverage Status](http://cc.popphp.org/coverage.php?comp=pop-crypt)](http://cc.popphp.org/pop-crypt/)

OVERVIEW
--------
`pop-crypt` provides various interfaces to a assist in creating and verifying encryption hashes.
The supported encryption hashes are:

* Crypt
* Bcrypt
* Md5
* Sha
* Mcrypt (2-way hashing)

`pop-crypt` is a component of the [Pop PHP Framework](http://www.popphp.org/).

INSTALL
-------

Install `pop-crypt` using Composer.

    composer require popphp/pop-crypt


BASIC USAGE
-----------

### Create and verify a hash with Crypt

Using crypt is the simplest way to create an encrypted hash. It's best to use
a strong, random salt for better security.

```php
$crypt = new Pop\Crypt\Crypt();
$crypt->setSalt($crypt->generateRandomString(32));
$hash  = $crypt->create('my-password');

// Outputs 'Lx8nDfxK6TbQg'
echo $hash;

if ($crypt->verify('bad-password', $hash)) {} // Returns false
if ($crypt->verify('my-password', $hash))  {} // Returns true
```

### Create and verify a hash with Bcrypt

Bcrypt is considered one of the stronger methods of creating encrypted hashes. With it,
you can specify the prefix and performance cost. The higher the cost, the stronger the hash.
However, the higher the cost, the longer it will take to generate the hash. The cost range
values are between '04' and '31'.

Again, it's best to use a strong salt for better security. In fact, it's considered a best
practice to use a strong random string as the salt, which the Bcrypt class generates
automatically for you if you don't specify one.

```php
$bcrypt = new Pop\Crypt\Bcrypt();
$bcrypt->setCost('12')
       ->setPrefix('$2y$');

$hash= $bcrypt->create('my-password');

// Outputs '$2y$12$OHZtOTlrNG1UTE5wUmpGQO2WJPFSzkhDErx2UHOvFEwU8/NosVYDe'
echo $hash;

if ($bcrypt->verify('bad-password', $hash)) {} // Returns false
if ($bcrypt->verify('my-password', $hash))  {} // Returns true
```

### Create and verify a hash with Md5

This isn't to be confused with the basic `md5()` function built into PHP. It is not recommended
to use that function for password hashing as it only generates a 32-character hexadecimal number
and is vulnerable to dictionary attacks.

As before, it's best to use a strong salt for better security. In fact, it's considered a best
practice to use a strong random string as the salt. Like Bcrypt, the Md5 class will automatically
generate a random salt for you if you don't specify one.

```php
$md5  = new Pop\Crypt\Md5();
$hash = $md5->create('my-password');

// Outputs '$1$TlBKWGtw$zdivNfpOUPWwJ3a1cUM1E/'
echo $hash;

if ($md5->verify('bad-password', $hash)) {} // Returns false
if ($md5->verify('my-password', $hash))  {} // Returns true
```

### Create and verify a hash with Sha

This isn't to be confused with the basic `sha1()` function built into PHP. Like `md5()`, it is
not recommended to use that function for password hashing as it only generates a 40-character
hexadecimal number and is vulnerable to dictionary attacks.

With the Sha class, you can set the bits (256 or 515) and rounds (between 1000 and 999999999),
which will affect the performance and strength of the hash.

As before, it's best to use a strong salt for better security. In fact, it's considered a best
practice to use a strong random string as the salt. Like Bcrypt and Md5, the Sha class will
automatically generate a random salt for you if you don't specify one.

```php
$sha  = new Pop\Crypt\Sha();
$sha->setBits512()
    ->setRounds(10000);

$hash = $sha->create('my-password');

// Outputs a big long hash '$6$rounds=10000$QlZOMkJZQVNBeEN...'
echo $hash;

if ($sha->verify('bad-password', $hash)) {} // Returns false
if ($sha->verify('my-password', $hash))  {} // Returns true
```

### Two-way encryption hashing with Mcrypt

Mcrypt provides a way to create a two-way encryption hash, in which you can create an unreadable
encrypted hash and then decrypt it later to retrieve the value of it.

```php
$mcrypt = new Pop\Crypt\Mcrypt();
```

You have several parameters that you can set with the Mcrypt class to help control the performance
and security of the hashing. These values are set by default, or you can set them yourself:

```php
$mcrypt->setCipher(MCRYPT_RIJNDAEL_256)
       ->setMode(MCRYPT_MODE_CBC)
       ->setSource(MCRYPT_RAND);
```

As with the others, it's best to use a strong salt for better security. In fact, it's considered
a best practice to use a strong random string as the salt. Like the others, the Mcrypt class will
automatically generate a random salt for you if you don't specify one.

```php
$hash = $mcrypt->create('my-password');

// Outputs a big long hash 'NGGe/i6XPKFGY4cvxZrSb4zBj1J0OYh...'
echo $hash;

if ($mcrypt->verify('bad-password', $hash)) {} // Returns false
if ($mcrypt->verify('my-password', $hash))  {} // Returns true
```

You can then retrieve the value of the hash by decrypting it:

```php
$decrypted = $mcrypt->decrypt($hash);

// Outputs 'my-password'
echo $decrypted;
```
