<?php

namespace PTLS\Extensions;

use PTLS\Core;

/**
 * https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
 *
 * The client uses the "signature_algorithms" extension to indicate to
 *   the server which signature/hash algorithm pairs may be used in
 *   digital signatures.  The "extension_data" field of this extension
 *   contains a "supported_signature_algorithms" value. 
 *
 *      enum {
 *          none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
 *          sha512(6), (255)
 *      } HashAlgorithm;
 *
 *      enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
 *        SignatureAlgorithm;
 *
 *      struct {
 *            HashAlgorithm hash;
 *            SignatureAlgorithm signature;
 *      } SignatureAndHashAlgorithm;
 *
 *      SignatureAndHashAlgorithm
 *        supported_signature_algorithms<2..2^16-2>;
 */
class SignatureAlgorithm extends ExtensionAbstract
{
    const TYPE_DEFAULT_RSA = 0x0201; //sha1 rsa

    const TYPE_SHA512_RSA = 0x0601;    
    const TYPE_SHA384_RSA = 0x0501;
    const TYPE_SHA256_RSA = 0x0401;

    private static $supportedAlgorithmList = [
        self::TYPE_SHA512_RSA,
        self::TYPE_SHA384_RSA,
        self::TYPE_SHA256_RSA,
    ];

    private $core;
    private $algorithm;

    public function __construct(Core $core)
    {
        $this->core = $core;
        $this->algorithm = null;
    }

    public function onEncodeClientHello($type, $data)
    {
        $core = $this->core;

        if( $type != TLSExtensions::TYPE_SIGNATURE_ALGORITHM )
            return; 

        $protoVersion = $core->getProtocolVersion();

        /*
         *   Note: this extension is not meaningful for TLS versions prior to 1.2.
         * Clients MUST NOT offer it if they are offering prior versions.
         * However, even if clients do offer it, the rules specified in [TLSEXT]
         * require servers to ignore extensions they do not understand.
         */
        if( $protoVersion < 32 )
            return;

        $length = Core::_unpack('n', $data[0] . $data[1]);
        $data = substr($data, 2);

        for( $i = 0; $i < $length; $i += 2 )
        {
            $hash = Core::_unpack('C', $data[$i]);
            $sig  = Core::_unpack('C', $data[$i+1]);

            $algorithm = $hash << 8 | $sig;

            if( in_array( $algorithm, self::$supportedAlgorithmList ) )
            {
                $this->algorithm = $algorithm;
                break;
            }
        }
    }

    public function onDecodeClientHello()
    {
        $sigData = '';

        foreach(self::$supportedAlgorithmList as $algorithm)
        {
            $sigData .= Core::_pack('C', $algorithm >> 8) . Core::_pack('C', $algorithm & 0x00ff);
        }
     
        $sigData = Core::_pack('n', strlen($sigData) ) . $sigData;

        $this->extType = TLSExtensions::TYPE_SIGNATURE_ALGORITHM;
        $this->length  = strlen($sigData);

        $data = $this->decodeHeader() . $sigData;

        return $data;
    }

    public function onDecodeServerHello(){}

    public function getAlgorithm()
    {
        $algorithm = is_null($this->algorithm) ? self::TYPE_DEFAULT_RSA : $this->algorithm;
        return [$algorithm >> 8, $algorithm & 0x00ff];
    }

    /**
     * Our version of md5sha1 signature as openssl doesn't support it
     */
    public function getSignatureMD5Sha1($dataSign, &$signature, $privateKey)
    {
        $hash = md5($dataSign, true) . sha1($dataSign, true);
        openssl_private_encrypt($hash, $signature, $privateKey);
    }

    public function getSignature($dataSign)
    {
        $core = $this->core;
        $privateKey = $core->getConfig('private_key');
        $protoVersion = $core->getProtocolVersion();

        /*
         * https://www.ietf.org/rfc/rfc2246.txt page 40
         *
         * select (SignatureAlgorithm)
         * {   case anonymous: struct { };
         *   case rsa:
         *       digitally-signed struct {
         *           opaque md5_hash[16];
         *           opaque sha_hash[20];
         *       };
         *   case dsa:
         *       digitally-signed struct {
         *           opaque sha_hash[20];
         *       };
         * } Signature;
         */
        if( $protoVersion < 32 )
        {
            $this->getSignatureMD5Sha1($dataSign, $signature, $privateKey);
            return $signature;
        }

        /*
         * https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
         *
         * If the client does not send the signature_algorithms extension, the
         * server MUST do the following:
         *
         * -  If the negotiated key exchange algorithm is one of (RSA, DHE_RSA,
         *    DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA), behave as if client had
         *    sent the value {sha1,rsa}.
         */
        if( is_null( $this->algorithm ) )
        {
            openssl_sign($dataSign, $signature, $privateKey, OPENSSL_ALGO_SHA1);
            return $signature;
        }

        switch( $this->algorithm )
        {
            case self::TYPE_SHA512_RSA:
                openssl_sign($dataSign, $signature, $privateKey, OPENSSL_ALGO_SHA512);
                break;
            case self::TYPE_SHA384_RSA:
                openssl_sign($dataSign, $signature, $privateKey, OPENSSL_ALGO_SHA384);
                break;
            case self::TYPE_SHA256_RSA:
                openssl_sign($dataSign, $signature, $privateKey, OPENSSL_ALGO_SHA256);
                break;
        }

        return $signature;
    }
}






