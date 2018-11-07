<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace AESGCM;

use Assert\Assertion;

final class AESGCM
{
    /**
     * @param string      $K          Key encryption key
     * @param string      $IV         Initialization vector
     * @param null|string $P          Data to encrypt (null for authentication)
     * @param null|string $A          Additional Authentication Data
     * @param int         $tag_length Tag length
     *
     * @return array
     */
    public static function encrypt($K, $IV, $P = null, $A = null, $tag_length = 128)
    {
        Assertion::string($K, 'The key encryption key must be a binary string.');
        $key_length = mb_strlen($K, '8bit') * 8;
        Assertion::inArray($key_length, [128, 192, 256], 'Bad key encryption key length.');
        Assertion::string($IV, 'The Initialization Vector must be a binary string.');
        Assertion::nullOrString($P, 'The data to encrypt must be null or a binary string.');
        Assertion::nullOrString($A, 'The Additional Authentication Data must be null or a binary string.');
        Assertion::integer($tag_length, 'Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');
        Assertion::inArray($tag_length, [128, 120, 112, 104, 96], 'Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');

        if (version_compare(PHP_VERSION, '7.1.0RC5') >= 0 && null !== $P) {
            return self::encryptWithPHP71($K, $key_length, $IV, $P, $A, $tag_length);
        } elseif (class_exists('\Crypto\Cipher')) {
            return self::encryptWithCryptoExtension($K, $key_length, $IV, $P, $A, $tag_length);
        }

        return self::encryptWithPHP($K, $key_length, $IV, $P, $A, $tag_length);
    }

    /**
     * This method will append the tag at the end of the ciphertext.
     *
     * @param string      $K          Key encryption key
     * @param string      $IV         Initialization vector
     * @param null|string $P          Data to encrypt (null for authentication)
     * @param null|string $A          Additional Authentication Data
     * @param int         $tag_length Tag length
     *
     * @return string
     */
    public static function encryptAndAppendTag($K, $IV, $P = null, $A = null, $tag_length = 128)
    {
        return implode(self::encrypt($K, $IV, $P, $A, $tag_length));
    }

    /**
     * @param string      $K          Key encryption key
     * @param string      $key_length Key length
     * @param string      $IV         Initialization vector
     * @param null|string $P          Data to encrypt (null for authentication)
     * @param null|string $A          Additional Authentication Data
     * @param int         $tag_length Tag length
     *
     * @return array
     */
    private static function encryptWithPHP71($K, $key_length, $IV, $P = null, $A = null, $tag_length = 128)
    {
        $mode = 'aes-'.($key_length).'-gcm';
        $T = null;
        $C = openssl_encrypt($P, $mode, $K, OPENSSL_RAW_DATA, $IV, $T, $A, $tag_length / 8);
        Assertion::true(false !== $C, 'Unable to encrypt the data.');

        return [$C, $T];
    }

    /**
     * @param string      $K          Key encryption key
     * @param string      $key_length Key length
     * @param string      $IV         Initialization vector
     * @param null|string $P          Data to encrypt (null for authentication)
     * @param null|string $A          Additional Authentication Data
     * @param int         $tag_length Tag length
     *
     * @return array
     */
    private static function encryptWithPHP($K, $key_length, $IV, $P = null, $A = null, $tag_length = 128)
    {
        list($J0, $v, $a_len_padding, $H) = self::common($K, $key_length, $IV, $A);

        $C = self::getGCTR($K, $key_length, self::getInc(32, $J0), $P);
        $u = self::calcVector($C);
        $c_len_padding = self::addPadding($C);

        $S = self::getHash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
        $T = self::getMSB($tag_length, self::getGCTR($K, $key_length, $J0, $S));

        return [$C, $T];
    }

    /**
     * @param string      $K          Key encryption key
     * @param string      $key_length Key length
     * @param string      $IV         Initialization vector
     * @param null|string $P          Data to encrypt (null for authentication)
     * @param null|string $A          Additional Authentication Data
     * @param int         $tag_length Tag length
     *
     * @return array
     */
    private static function encryptWithCryptoExtension($K, $key_length, $IV, $P = null, $A = null, $tag_length = 128)
    {
        $cipher = \Crypto\Cipher::aes(\Crypto\Cipher::MODE_GCM, $key_length);
        $cipher->setAAD($A);
        $cipher->setTagLength($tag_length / 8);
        $C = $cipher->encrypt($P, $K, $IV);
        $T = $cipher->getTag();

        return [$C, $T];
    }

    /**
     * @param string      $K  Key encryption key
     * @param string      $IV Initialization vector
     * @param string|null $C  Data to encrypt (null for authentication)
     * @param string|null $A  Additional Authentication Data
     * @param string      $T  Tag
     *
     * @return string
     */
    public static function decrypt($K, $IV, $C, $A, $T)
    {
        Assertion::string($K, 'The key encryption key must be a binary string.');
        $key_length = mb_strlen($K, '8bit') * 8;
        Assertion::inArray($key_length, [128, 192, 256], 'Bad key encryption key length.');
        Assertion::string($IV, 'The Initialization Vector must be a binary string.');
        Assertion::nullOrString($C, 'The data to encrypt must be null or a binary string.');
        Assertion::nullOrString($A, 'The Additional Authentication Data must be null or a binary string.');

        $tag_length = self::getLength($T);
        Assertion::integer($tag_length, 'Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');
        Assertion::inArray($tag_length, [128, 120, 112, 104, 96], 'Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');

        if (version_compare(PHP_VERSION, '7.1.0RC5') >= 0 && null !== $C) {
            return self::decryptWithPHP71($K, $key_length, $IV, $C, $A, $T);
        } elseif (class_exists('\Crypto\Cipher')) {
            return self::decryptWithCryptoExtension($K, $key_length, $IV, $C, $A, $T, $tag_length);
        }

        return self::decryptWithPHP($K, $key_length, $IV, $C, $A, $T, $tag_length);
    }

    /**
     * This method should be used if the tag is appended at the end of the ciphertext.
     * It is used by some AES GCM implementations such as the Java one.
     *
     * @param string      $K          Key encryption key
     * @param string      $IV         Initialization vector
     * @param string|null $Ciphertext Data to encrypt (null for authentication)
     * @param string|null $A          Additional Authentication Data
     * @param int         $tag_length Tag length
     *
     * @return string
     *
     * @see self::encryptAndAppendTag
     */
    public static function decryptWithAppendedTag($K, $IV, $Ciphertext = null, $A = null, $tag_length = 128)
    {
        $tag_length_in_bits = $tag_length / 8;
        $C = mb_substr($Ciphertext, 0, -$tag_length_in_bits, '8bit');
        $T = mb_substr($Ciphertext, -$tag_length_in_bits, null, '8bit');

        return self::decrypt($K, $IV, $C, $A, $T);
    }

    /**
     * @param string      $K          Key encryption key
     * @param string      $key_length Key length
     * @param string      $IV         Initialization vector
     * @param string|null $C          Data to encrypt (null for authentication)
     * @param string|null $A          Additional Authentication Data
     * @param string      $T          Tag
     *
     * @return string
     */
    private static function decryptWithPHP71($K, $key_length, $IV, $C, $A, $T)
    {
        $mode = 'aes-'.($key_length).'-gcm';
        $P = openssl_decrypt(null === $C ? '' : $C, $mode, $K, OPENSSL_RAW_DATA, $IV, $T, null === $A ? '' : $A);
        Assertion::true(false !== $P, 'Unable to decrypt or to verify the tag.');

        return $P;
    }

    /**
     * @param string      $K          Key encryption key
     * @param string      $key_length Key length
     * @param string      $IV         Initialization vector
     * @param string|null $C          Data to encrypt (null for authentication)
     * @param string|null $A          Additional Authentication Data
     * @param string      $T          Tag
     * @param int         $tag_length Tag length
     *
     * @return string
     */
    private static function decryptWithPHP($K, $key_length, $IV, $C, $A, $T, $tag_length = 128)
    {
        list($J0, $v, $a_len_padding, $H) = self::common($K, $key_length, $IV, $A);

        $P = self::getGCTR($K, $key_length, self::getInc(32, $J0), $C);

        $u = self::calcVector($C);
        $c_len_padding = self::addPadding($C);

        $S = self::getHash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
        $T1 = self::getMSB($tag_length, self::getGCTR($K, $key_length, $J0, $S));
        Assertion::eq($T1, $T, 'Unable to decrypt or to verify the tag.');

        return $P;
    }

    /**
     * @param string      $K          Key encryption key
     * @param string      $key_length Key length
     * @param string      $IV         Initialization vector
     * @param string|null $C          Data to encrypt (null for authentication)
     * @param string|null $A          Additional Authentication Data
     * @param string      $T          Tag
     * @param int         $tag_length Tag length
     *
     * @return string
     */
    private static function decryptWithCryptoExtension($K, $key_length, $IV, $C, $A, $T, $tag_length = 128)
    {
        $cipher = \Crypto\Cipher::aes(\Crypto\Cipher::MODE_GCM, $key_length);
        $cipher->setTag($T);
        $cipher->setAAD($A);
        $cipher->setTagLength($tag_length / 8);

        return $cipher->decrypt($C, $K, $IV);
    }

    /**
     * @param $K
     * @param $key_length
     * @param $IV
     * @param $A
     *
     * @return array
     */
    private static function common($K, $key_length, $IV, $A)
    {
        $H = openssl_encrypt(str_repeat("\0", 16), 'aes-'.($key_length).'-ecb', $K, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA); //---
        $iv_len = self::getLength($IV);

        if (96 === $iv_len) {
            $J0 = $IV.pack('H*', '00000001');
        } else {
            $s = self::calcVector($IV);
            Assertion::eq(($s + 64) % 8, 0, 'Unable to decrypt or to verify the tag.');

            $packed_iv_len = pack('N', $iv_len);
            $iv_len_padding = str_pad($packed_iv_len, 8, "\0", STR_PAD_LEFT);
            $hash_X = $IV.str_pad('', ($s + 64) / 8, "\0").$iv_len_padding;
            $J0 = self::getHash($H, $hash_X);
        }
        $v = self::calcVector($A);
        $a_len_padding = self::addPadding($A);

        return [$J0, $v, $a_len_padding, $H];
    }

    /**
     * @param string $value
     *
     * @return int
     */
    private static function calcVector($value)
    {
        return (128 * ceil(self::getLength($value) / 128)) - self::getLength($value);
    }

    /**
     * @param string $value
     *
     * @return string
     */
    private static function addPadding($value)
    {
        return str_pad(pack('N', self::getLength($value)), 8, "\0", STR_PAD_LEFT);
    }

    /**
     * @param string $x
     *
     * @return int
     */
    private static function getLength($x)
    {
        return mb_strlen($x, '8bit') * 8;
    }

    /**
     * @param int $num_bits
     * @param int $x
     *
     * @return string
     */
    private static function getMSB($num_bits, $x)
    {
        $num_bytes = $num_bits / 8;

        return mb_substr($x, 0, $num_bytes, '8bit');
    }

    /**
     * @param int $num_bits
     * @param int $x
     *
     * @return string
     */
    private static function getLSB($num_bits, $x)
    {
        $num_bytes = ($num_bits / 8);

        return mb_substr($x, -$num_bytes, null, '8bit');
    }

    /**
     * @param int $s_bits
     * @param int $x
     *
     * @return string
     */
    private static function getInc($s_bits, $x)
    {
        $lsb = self::getLSB($s_bits, $x);
        $X = self::toUInt32Bits($lsb) + 1;
        $res = self::getMSB(self::getLength($x) - $s_bits, $x).pack('N', $X);

        return $res;
    }

    /**
     * @param string $bin
     *
     * @return mixed
     */
    private static function toUInt32Bits($bin)
    {
        list(, $h, $l) = unpack('n*', $bin);

        return $l + ($h * 0x010000);
    }

    /**
     * @param $X
     * @param $Y
     *
     * @return string
     */
    private static function getProduct($X, $Y)
    {
        $R = pack('H*', 'E1').str_pad('', 15, "\0");
        $Z = str_pad('', 16, "\0");
        $V = $Y;

        $parts = str_split($X, 4);
        $x = sprintf('%032b%032b%032b%032b', self::toUInt32Bits($parts[0]), self::toUInt32Bits($parts[1]), self::toUInt32Bits($parts[2]), self::toUInt32Bits($parts[3]));
        $lsb_mask = "\1";
        for ($i = 0; $i < 128; $i++) {
            if ($x[$i]) {
                $Z = self::getBitXor($Z, $V);
            }
            $lsb_8 = mb_substr($V, -1, null, '8bit');
            if (ord($lsb_8 & $lsb_mask)) {
                $V = self::getBitXor(self::shiftStringToRight($V), $R);
            } else {
                $V = self::shiftStringToRight($V);
            }
        }

        return $Z;
    }

    /**
     * @param string $input
     *
     * @return string
     */
    private static function shiftStringToRight($input)
    {
        $width = 4;
        $parts = array_map('self::toUInt32Bits', str_split($input, $width));
        $runs = count($parts);

        for ($i = $runs - 1; $i >= 0; $i--) {
            if ($i) {
                $lsb1 = $parts[$i - 1] & 0x00000001;
                if ($lsb1) {
                    $parts[$i] = ($parts[$i] >> 1) | 0x80000000;
                    $parts[$i] = pack('N', $parts[$i]);
                    continue;
                }
            }
            $parts[$i] = ($parts[$i] >> 1) & 0x7FFFFFFF;
            $parts[$i] = pack('N', $parts[$i]);
        }
        $res = implode('', $parts);

        return $res;
    }

    /**
     * @param string $H
     * @param string $X
     *
     * @return mixed
     */
    private static function getHash($H, $X)
    {
        $Y = [];
        $Y[0] = str_pad('', 16, "\0");
        $num_blocks = (int) (mb_strlen($X, '8bit') / 16);
        for ($i = 1; $i <= $num_blocks; $i++) {
            $Y[$i] = self::getProduct(self::getBitXor($Y[$i - 1], mb_substr($X, ($i - 1) * 16, 16, '8bit')), $H);
        }

        return $Y[$num_blocks];
    }

    /**
     * @param string $K
     * @param int    $key_length
     * @param string $ICB
     * @param string $X
     *
     * @return string
     */
    private static function getGCTR($K, $key_length, $ICB, $X)
    {
        if (empty($X)) {
            return '';
        }

        $n = (int) ceil(self::getLength($X) / 128);
        $CB = [];
        $Y = [];
        $CB[1] = $ICB;
        for ($i = 2; $i <= $n; $i++) {
            $CB[$i] = self::getInc(32, $CB[$i - 1]);
        }
        $mode = 'aes-'.($key_length).'-ecb';
        for ($i = 1; $i < $n; $i++) {
            $C = openssl_encrypt($CB[$i], $mode, $K, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA);
            $Y[$i] = self::getBitXor(mb_substr($X, ($i - 1) * 16, 16, '8bit'), $C);
        }

        $Xn = mb_substr($X, ($n - 1) * 16, null, '8bit');
        $C = openssl_encrypt($CB[$n], $mode, $K, OPENSSL_NO_PADDING | OPENSSL_RAW_DATA);
        $Y[$n] = self::getBitXor($Xn, self::getMSB(self::getLength($Xn), $C));

        return implode('', $Y);
    }

    /**
     * @param string $o1
     * @param string $o2
     *
     * @return string
     */
    private static function getBitXor($o1, $o2)
    {
        $xorWidth = PHP_INT_SIZE;
        $o1 = str_split($o1, $xorWidth);
        $o2 = str_split($o2, $xorWidth);
        $res = '';
        $runs = count($o1);
        for ($i = 0; $i < $runs; $i++) {
            $res .= $o1[$i] ^ $o2[$i];
        }

        return $res;
    }
}
