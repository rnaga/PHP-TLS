<?php

namespace PTLS;

use PTLS\TLS;

/**
 * Pseudorandom Function
 */
class Prf
{
    private $core;

    function __construct(Core $core)
    {
        $this->core = $core;
    }

    public function prf($length, $secret, $label, $seed)
    {
        $core = $this->core;
        $protoVersion = $core->getProtocolVersion();

        if( $protoVersion == 31 )
        {
            return $this->prf31($length, $secret, $label, $seed);
        }
        else
        {
            return $this->prf32($length, $secret, $label, $seed);
        }
    }

    /**
     * Generate master secret from premaster
     */
    public function getMaster($preMaster, $clientRandom, $serverRandom)
    {
        $masterSecretLength = 48;
        $seed = $clientRandom . $serverRandom;

        $masterSecret = $this->prf($masterSecretLength, $preMaster, "master secret", $seed);
        return $masterSecret;
    }


    /**
     * Generate secret keys
     */
    public function getKeys($masterSecret, $clientRandom, $serverRandom)
    {
        $core = $this->core;
        $cipherSuite = $core->cipherSuite;

        $macLen = $cipherSuite->getMACLen(); 
        $keyLen = $cipherSuite->getKeyLen(); 
        $ivLen  = $cipherSuite->getIVLen();  

        $seed = $serverRandom . $clientRandom;

        /*
         * https://tools.ietf.org/html/rfc5246#section-6.3
         *
         * client_write_MAC_key[SecurityParameters.mac_key_length]
         * server_write_MAC_key[SecurityParameters.mac_key_length]
         * client_write_key[SecurityParameters.enc_key_length]
         * server_write_key[SecurityParameters.enc_key_length]
         * client_write_IV[SecurityParameters.fixed_iv_length]
         * server_write_IV[SecurityParameters.fixed_iv_length]
         */
        $offset = 0;
        $length = 2*$macLen + 2*$keyLen + 2*$ivLen;
        $keys   = $this->prf($length, $masterSecret, "key expansion", $seed);
      
        $clientMAC = substr($keys, $offset, $macLen);
        $offset += $macLen;

        $serverMAC = substr($keys, $offset, $macLen);
        $offset += $macLen;

        $clientKey = substr($keys, $offset, $keyLen);
        $offset += $keyLen;

        $serverKey = substr($keys, $offset, $keyLen);
        $offset += $keyLen;

        $clientIV = substr($keys, $offset, $ivLen);
        $offset += $ivLen;

        $serverIV = substr($keys, $offset, $ivLen);

        return [
            'client' => ['MAC' => $clientMAC, 'Key' => $clientKey, 'IV' => $clientIV],
            'server' => ['MAC' => $serverMAC, 'Key' => $serverKey, 'IV' => $serverIV],
        ];
    }

    /**
     * For TLS1.1
     */
    public function prf31($length, $secret, $label, $seed)
    {
        $labelAndSeed = $label . $seed;

        $LS1 = substr($secret, 0, ceil(strlen($secret))/2);
        $LS2 = substr($secret, ceil(strlen($secret)/2));

        $md5  = $this->pHash($length, $LS1, $labelAndSeed, "md5");
        $sha1 = $this->pHash($length, $LS2, $labelAndSeed, "sha1");

        $result = [];
        for( $i = 0; $i < strlen($sha1); $i++)
            $result[$i] = ( $md5[$i] ) ^ ( $sha1[$i] );

        return implode("", $result);
    }

    /**
     * For TLS1.2
     */
    public function prf32($length, $secret, $label, $seed)
    {
        $core = $this->core;
        $cipherSuite = $core->cipherSuite;

        $labelAndSeed = $label . $seed;
        $hash = $this->pHash($length, $secret, $labelAndSeed, $cipherSuite->getHashAlogV33());
        return $hash;
    }

    /**
     * https://tools.ietf.org/html/rfc5246#section-5
     *
     * HMAC and the Pseudorandom Function
     */
    public function pHash($length, $secret, $seed, $hashType)
    {
        $j = 0;

        $A = hash_hmac($hashType, $seed, $secret, true);

        $result = null;
        while( $j < $length )
        {
            $b = hash_hmac($hashType, $A . $seed, $secret, true);

            $blen = strlen($b);

            if( $j+$blen > $length )
                $result .= substr($b, 0, $length - $j);
            else
                $result .= $b;

            $A = hash_hmac($hashType, $A, $secret, true);

            $j += $blen;
        }

        return $result;
    }
}



