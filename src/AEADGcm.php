<?php

namespace PTLS;

use AESGCM\AESGCM;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class AEADGcm
{
    // A tag is alway 16 bytes long
    const TAG_LEN = 16;

    /**
     * PHP supports AES GCM from version 7.1
     *
     * https://github.com/php/php-src/pull/1716
     * https://wiki.php.net/rfc/openssl_aead
     *
     */
    private static function useOpenSSL()
    {
        return (version_compare(PHP_VERSION, '7.1') >= 0 ) ? true : false;
    }

    /**
     * https://github.com/bukka/php-crypto
     *
     * Objective PHP binding of OpenSSL Crypto library
     *
     */
    private static function useSO()
    {
        return class_exists('\Crypto\Cipher') ? true : false;
    }

    private static function bitLen($password)
    {
        // 128(16), 192(24) or 256(32)
        $l = strlen($password);

        if( $l != 16 && $l != 24 && $l != 32 )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Invalid gcm key length: $l");

        return $l * 8;
    }

    private static function getMethod($password)
    {
        return "aes-" . self::bitLen($password) . "-gcm";
    }

    public static function encrypt($data, $password, $IV, $AAD)
    {
        if( self::useOpenSSL() )
        {
            $method = self::getMethod($password);
            $encrypt = openssl_encrypt($data, $method, $password, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $IV, $tag, $AAD);
        }
        else if( self::useSO() )
        {
            try{
                $cipher = \Crypto\Cipher::aes(\Crypto\Cipher::MODE_GCM, self::bitLen($password));
                $cipher->setAAD($AAD);
                $encrypt = $cipher->encrypt($data, $password, $IV);
                $tag = $cipher->getTag();
            }catch(\Exception $e){
                //echo $e->getMessage();
                return false;
            }
        }
        else
        {
            try{
                list($encrypt, $tag) = AESGCM::encrypt($password, $IV, $data, $AAD);
            }catch(\Exception $e){
                //echo $e->getMessage();
                return false;
            }
        }

        return $encrypt . $tag;
     }

    public static function decrypt($encData, $password, $IV, $AAD)
    {
        /*
         * https://tools.ietf.org/html/rfc5116#section-5.1
         * 
         * An authentication tag with a length of 16 octets (128
         * bits) is used.  The AEAD_AES_128_GCM ciphertext is formed by
         * appending the authentication tag provided as an output to the GCM
         * encryption operation to the ciphertext that is output by that
         * operation. 
         *
         * ciphertext is exactly 16 octets longer than its
         * corresponding plaintext.
         */
        if( strlen($encData) < self::TAG_LEN )
            return false;

        // Get the tag appended to cipher text
        $tag = substr($encData, strlen($encData) - self::TAG_LEN, self::TAG_LEN);

        // Resize the cipher text
        $encData = substr($encData, 0, strlen($encData) - self::TAG_LEN);

        if( self::useOpenSSL() )
        {
            $method = self::getMethod($password);
            $data = openssl_decrypt($encData, $method, $password, OPENSSL_RAW_DATA, $IV, $tag, $AAD);
        }
        else if( self::useSO() )
        {
            try{
                $cipher = \Crypto\Cipher::aes(\Crypto\Cipher::MODE_GCM, self::bitLen($password));
                $cipher->setTag($tag);
                $cipher->setAAD($AAD);
                $data = $cipher->decrypt($encData, $password, $IV);
            }catch(\Exception $e){
                return false;
            }
        }
        else
        {
            try{
                $data = AESGCM::decrypt($password, $IV, $encData, $AAD, $tag);
            }catch(\Exception $e){
                //echo $e->getMessage();
                return false;
            }
        }

        return $data;
     }
}


