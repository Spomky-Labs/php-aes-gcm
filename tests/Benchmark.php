<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

 include_once __DIR__.'/../vendor/autoload.php';

use AESGCM\AESGCM;
use Assert\Assertion;

/**
 * This function allows developpers to test the encryption performance of the library on their environnement.
 *
 * @param int $nb Number of encryption/decryption to perform
 */
function runEncryptionBenchmark($nb = 1000)
{
    Assertion::integer($nb, 'The argument must be an integer');
    Assertion::greaterThan($nb, 1, 'The argument must be greater than 1');

    $K = hex2bin('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
    $IV = hex2bin('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b');
    $P = hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
    $A = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');

    print_r('################################'.PHP_EOL);
    print_r('# AES-GCM ENCRYPTION BENCHMARK #'.PHP_EOL);
    print_r('################################'.PHP_EOL);

    $time = -microtime(true);
    for ($i = 0; $i < $nb; $i++) {
        AESGCM::encrypt($K, $IV, $P, $A);
    }
    $time += microtime(true);
    $ops = $nb / $time;
    printf('%f OPS (tested on %d encryptions)'.PHP_EOL, $ops, $nb);

    print_r('################################'.PHP_EOL);
}

/**
 * This function allows developpers to test the decryption performance of the library on their environnement.
 *
 * @param int $nb Number of encryption/decryption to perform
 */
function runDecryptionBenchmark($nb = 1000)
{
    Assertion::integer($nb, 'The argument must be an integer');
    Assertion::greaterThan($nb, 1, 'The argument must be greater than 1');

    $K = hex2bin('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
    $IV = hex2bin('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b');
    $C = hex2bin('5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f');
    $A = hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
    $T = hex2bin('a44a8266ee1c8eb0c8b5d4cf5ae9f19a');

    print_r('################################'.PHP_EOL);
    print_r('# AES-GCM DECRYPTION BENCHMARK #'.PHP_EOL);
    print_r('################################'.PHP_EOL);

    $time = -microtime(true);
    for ($i = 0; $i < $nb; $i++) {
        AESGCM::decrypt($K, $IV, $C, $A, $T);
    }
    $time += microtime(true);
    $ops = $nb / $time;
    printf('%f OPS (tested on %d encryptions)'.PHP_EOL, $ops, $nb);

    print_r('################################'.PHP_EOL);
}

runEncryptionBenchmark();
runDecryptionBenchmark();
