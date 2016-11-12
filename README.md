AES GCM (Galois Counter Mode) PHP Implementation
====================================================

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
[![License](https://poser.pugx.org/Spomky-Labs/php-aes-gcm/license.png)](https://packagist.org/packages/Spomky-Labs/php-aes-gcm)


# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least ![PHP 5.4+](https://img.shields.io/badge/PHP-5.4%2B-ff69b4.svg).

It has been successfully tested using `PHP 5.4`, `PHP 5.5`, `PHP 5.6`, `HHVM` and `PHP 7` (stable and nightly branches).

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require "spomky-labs/php-aes-gcm"
```

# How to use

```php
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
