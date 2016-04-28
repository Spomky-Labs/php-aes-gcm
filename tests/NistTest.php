<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test;

use AESGCM\AESGCM;

class NistTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @see http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
     *
     * @dataProvider dataVectors
     */
    public function testVectors($K, $P, $A, $IV, $expected_C, $expected_T)
    {
        list ($C, $T) = AESGCM::encrypt($K, $IV, $P, $A);

        $this->assertEquals($C, $expected_C);
        $this->assertEquals($T, $expected_T);
        
        $computed_P = AESGCM::decrypt($K, $IV, $C, $A, $T);

        $this->assertEquals($P, $computed_P);
    }

    public function dataVectors()
    {
        return [
            [
                hex2bin('00000000000000000000000000000000'), // K
                null, // P
                null, // A
                hex2bin('000000000000000000000000'), // IV
                null, // Expected C
                hex2bin('58e2fccefa7e3061367f1d57a4e7455a'), // Expected T
            ],
            [
                hex2bin('00000000000000000000000000000000'), // K
                hex2bin('00000000000000000000000000000000'), // P
                null, // A
                hex2bin('000000000000000000000000'), // IV
                hex2bin('0388dace60b6a392f328c2b971b2fe78'), // Expected C
                hex2bin('ab6e47d42cec13bdf53a67b21257bddf'), // Expected T
            ],
            [
                hex2bin('feffe9928665731c6d6a8f9467308308'), // K
                hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'), // P
                null, // A
                hex2bin('cafebabefacedbaddecaf888'), // IV
                hex2bin('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985'), // Expected C
                hex2bin('4d5c2af327cd64a62cf35abd2ba6fab4'), // Expected T
            ],
            [
                hex2bin('feffe9928665731c6d6a8f9467308308'), // K
                hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'), // P
                hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2'), // A
                hex2bin('cafebabefacedbaddecaf888'), // IV
                hex2bin('42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091'), // Expected C
                hex2bin('5bc94fbc3221a5db94fae95ae7121a47'), // Expected T
            ],
            [
                hex2bin('feffe9928665731c6d6a8f9467308308'), // K
                hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'), // P
                hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2'), // A
                hex2bin('cafebabefacedbad'), // IV
                hex2bin('61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598'), // Expected C
                hex2bin('3612d2e79e3b0785561be14aaca2fccb'), // Expected T
            ],
            [
                hex2bin('feffe9928665731c6d6a8f9467308308'), // K
                hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'), // P
                hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2'), // A
                hex2bin('9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b'), // IV
                hex2bin('8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5'), // Expected C
                hex2bin('619cc5aefffe0bfa462af43c1699d050'), // Expected T
            ],
            [
                hex2bin('000000000000000000000000000000000000000000000000'), // K
                null, // P
                null, // A
                hex2bin('000000000000000000000000'), // IV
                null, // Expected C
                hex2bin('cd33b28ac773f74ba00ed1f312572435'), // Expected T
            ],
            [
                hex2bin('000000000000000000000000000000000000000000000000'), // K
                hex2bin('00000000000000000000000000000000'), // P
                null, // A
                hex2bin('000000000000000000000000'), // IV
                hex2bin('98e7247c07f0fe411c267e4384b0f600'), // Expected C
                hex2bin('2ff58d80033927ab8ef4d4587514f0fb'), // Expected T
            ],
            [
                hex2bin('feffe9928665731c6d6a8f9467308308feffe9928665731c'), // K
                hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'), // P
                null, // A
                hex2bin('cafebabefacedbaddecaf888'), // IV
                hex2bin('3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256'), // Expected C
                hex2bin('9924a7c8587336bfb118024db8674a14'), // Expected T
            ],
            [
                hex2bin('feffe9928665731c6d6a8f9467308308feffe9928665731c'), // K
                hex2bin('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39'), // P
                hex2bin('feedfacedeadbeeffeedfacedeadbeefabaddad2'), // A
                hex2bin('cafebabefacedbaddecaf888'), // IV
                hex2bin('3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710'), // Expected C
                hex2bin('2519498e80f1478f37ba55bd6d27618c'), // Expected T
            ],
        ];
    }
}
