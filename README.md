AES GCM (Galois Counter Mode) PHP Implementation
====================================================

Help me out for a couple of :beers:!

[![Beerpay](https://beerpay.io/Spomky-Labs/php-aes-gcm/badge.svg?style=beer-square)](https://beerpay.io/Spomky-Labs/php-aes-gcm)  [![Beerpay](https://beerpay.io/Spomky-Labs/php-aes-gcm/make-wish.svg?style=flat-square)](https://beerpay.io/Spomky-Labs/php-aes-gcm?focus=wish)

----
[![Gitter](https://badges.gitter.im/Spomky-Labs/php-aes-gcm.svg)](https://gitter.im/Spomky-Labs/php-aes-gcm?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/php-aes-gcm/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/php-aes-gcm/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/Spomky-Labs/php-aes-gcm/badge.svg?branch=master)](https://coveralls.io/github/Spomky-Labs/php-aes-gcm?branch=master)

[![Build Status](https://travis-ci.org/Spomky-Labs/php-aes-gcm.svg?branch=master)](https://travis-ci.org/Spomky-Labs/php-aes-gcm)
[![HHVM Status](http://hhvm.h4cc.de/badge/spomky-labs/php-aes-gcm.svg)](http://hhvm.h4cc.de/package/spomky-labs/php-aes-gcm)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/php-aes-gcm/badge.svg)](https://travis-ci.org/Spomky-Labs/php-aes-gcm)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/1460711c-d11d-486c-a73a-8290d3e03460/big.png)](https://insight.sensiolabs.com/projects/1460711c-d11d-486c-a73a-8290d3e03460)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/php-aes-gcm/v/stable.png)](https://packagist.org/packages/Spomky-Labs/php-aes-gcm)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/php-aes-gcm/downloads.png)](https://packagist.org/packages/Spomky-Labs/php-aes-gcm)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/php-aes-gcm/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/php-aes-gcm)
[![License](https://poser.pugx.org/Spomky-Labs/php-aes-gcm/license.png)](https://packagist.org/packages/Spomky-Labs/php-aes-gcm) [![GuardRails badge](https://badges.production.guardrails.io/Spomky-Labs/php-aes-gcm.svg)](https://www.guardrails.io)


# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least ![PHP 5.4+](https://img.shields.io/badge/PHP-5.4%2B-ff69b4.svg).

It has been successfully tested using `PHP 5.4` to `PHP 7.1`, `HHVM` and nightly branches.

If you use PHP 7.1+, this library has very good performance. **If you do not use PHP 7.1+, we highly recommend you to install the [PHP Crypto extension](https://github.com/bukka/php-crypto).**
This extension drastically increase the performance of this library. With our pure PHP method, you will have low performance.

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require "spomky-labs/php-aes-gcm"
```

# How to use

```php
<?php

use AESGCM\AESGCM;

// The Key Encryption Key
$K = hex2bin('feffe9928665731c6d6a8f9467308308feffe9928665731c');

// The data to encrypt (can be null for authentication)
$P = hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');

// Additional Authenticated Data
$A = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');

// Initialization Vector
$IV = hex2bin('cafebabefacedbaddecaf888');

// $C is the encrypted data ($C is null if $P is null)
// $T is the associated tag
list($C, $T) = AESGCM::encrypt($K, $IV, $P, $A);
// The value of $C should be hex2bin('3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710')
// The value of $T should be hex2bin('2519498e80f1478f37ba55bd6d27618c')

$P = AESGCM::decrypt($K, $IV, $C, $A, $T);
// The value of $P should be hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
```

## Appended Tag

Some implementations of this cypher may append the tag at the end of the ciphertext.
This is commonly used by the Java implementation for example.

This library provides an easy way to produce such a ciphertext and read it.

```php
<?php

use AESGCM\AESGCM;

// The values $K, $P, $A, $IV hereafter have the same meaning as above

// $C is the encrypted data with the appended tag
$C = AESGCM::encryptAndAppendTag($K, $IV, $P, $A);
// The value of $C should be hex2bin('3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda27102519498e80f1478f37ba55bd6d27618c')

$P = AESGCM::decryptWithAppendedTag($K, $IV, $C, $A);
// The value of $P should be hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b392519498e80f1478f37ba55bd6d27618c')
```

## Tag Length

By default the tag length is 128 bits. This value is highly recommended, however you may need to use another tag length.
As per the cypher specification, the tag length could be 128, 120, 112, 104 or 96 bits.

```php
<?php

use AESGCM\AESGCM;

// The values $K, $P, $A, $IV hereafter have the same meaning as above
$TL = 96; // In this example the tag length will be 96 bits

list($C, $T) = AESGCM::encrypt($K, $IV, $P, $A, $TL);
// The value of $C should be hex2bin('3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710')
// The value of $T should be hex2bin('2519498e80f1478f37ba55bd')
```

The tag length is automatically calculated during the decryption operation with the method `AESGCM::decrypt`.
However, if the tag is appended at the end of the ciphertext and if it is not 128 bits, then it must be set:

```php
<?php

// The values $K, $IV, $C, $A hereafter have the same meaning as above
$TL = 96; // In this example the tag length will be 96 bits

$P = AESGCM::decryptWithAppendedTag($K, $IV, $C, $A, $TL);
```

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome.
The best contribution you could provide is by fixing the [opened issues where help is wanted](https://github.com/Spomky-Labs/php-aes-gcm/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

Please make sure to [follow these best practices](doc/Contributing.md).

# Benchmark

In the `test` folder, a little script to run encryption and decryption benchmarks is available.
You can run it on your environment to check how many time the encryption/decryption operations take.

```sh
php ./tests/Benchmark.php
```

# Licence

This library is release under [MIT licence](LICENSE).
