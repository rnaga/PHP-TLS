<?php

namespace PTLS;

use PTLS\Exceptions\TLSException;

class X509
{
    public static $pemCrtBegin = '-----BEGIN CERTIFICATE-----';
    public static $pemCrtEnd   = '-----END CERTIFICATE-----';

    public static function crtDerToPem($der)
    {
        $pem  = self::$pemCrtBegin . "\n"
              . chunk_split(base64_encode($der), 64)
              . self::$pemCrtEnd;

        return $pem;
    }

    public static function verifyCrt($der)
    {
        $pem = self::crtDerToPem($der);
        $crt = openssl_x509_parse($pem);

        return is_array( $crt ) ? true : false;
    }

    public static function crtPemToDer($pems)
    {
        $arrPems = explode(self::$pemCrtBegin, $pems);
        $arrPems = array_splice($arrPems, 1);

        $crtDers = [];

        foreach( $arrPems as $pem )
        {
            $pem = str_replace(self::$pemCrtEnd, '', $pem);
            $der = base64_decode(str_replace("\n", '', $pem));

            if( !self::verifyCrt($der) )
                throw new TLSException("Invalid Certificate");

            $crtDers[] = $der;
        }

        return $crtDers;
    }

    /**
     *  Get the pem file, and convert to der
     */
    public static function crtFilePemToDer(array $files)
    {
        if( !count( $files ) )
            throw new TLSException("No certificate files");

        $pem = '';

        foreach( $files as $file )
        {
            $pem .= file_get_contents($file);
        }

        return self::crtPemToDer($pem);
    }

    public static function getPrivateKey($file, $passCode = "")
    {
        $privateKey = file_get_contents($file);
        return openssl_get_privatekey($privateKey, $passCode);
    }


    public static function getPublicKey(array $crtDers)
    {
        $pem = X509::crtDerToPem($crtDers[0]);
        $publicKey = openssl_pkey_get_public($pem);

        return $publicKey;
    }
}







