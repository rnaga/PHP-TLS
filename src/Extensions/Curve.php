<?php

namespace PTLS\Extensions;

use PTLS\Core;
use PTLS\Handshake\HandshakeFactory;
use PTLS\Handshake\HandshakeType;
use PTLS\EcDH;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

/**
  * https://tools.ietf.org/html/rfc4492#section-5.1
  *
  * enum { elliptic_curves(10), ec_point_formats(11) } ExtensionType;
  *
  *   elliptic_curves (Supported Elliptic Curves Extension):   Indicates
  *      the set of elliptic curves supported by the client.  For this
  *      extension, the opaque extension_data field contains
  *      EllipticCurveList.  See Section 5.1.1 for details.
  *
  *   ec_point_formats (Supported Point Formats Extension):   Indicates the
  *      set of point formats that the client can parse.  For this
  *      extension, the opaque extension_data field contains
  *      ECPointFormatList.  See Section 5.1.2 for details.
 */
class Curve extends ExtensionAbstract
{
    private $core;
    private $namedCurveType;
    private $isUncompressed;
    private $ecdh;
    private $preMaster;

    public function __construct(Core $core)
    {
        $this->core = $core;
        $this->isUncompressed = false;
    }

    public function isEnabled()
    {
        return $this->isUncompressed && !is_null( $this->namedCurveType );
    }

    public function onEncodeClientHello($type, $data)
    {
        $core = $this->core;

        switch($type)
        {
            /*
             * elliptic_curves(10)
             *
             * https://tools.ietf.org/html/rfc4492#section-5.1.1
             *
             * struct {
             *   NamedCurve elliptic_curve_list<1..2^16-1>
             * } EllipticCurveList;
             */
            case TLSExtensions::TYPE_ELLIPTIC_CURVES:
                $length = Core::_unpack('n', $data[0] . $data[1]);
                $data = substr($data, 2);

                for( $i = 0; $i < $length; $i += 2 )
                {
                    $namedCurveType = Core::_unpack('n', $data[$i] . $data[$i+1]);

                    if( Ecdh::isSupported($namedCurveType) ) 
                    {
                        $this->namedCurveType = $namedCurveType;  
                        break;
                    }                      
                }

                break;

            case TLSExtensions::TYPE_EC_POINT_FORMATS:
                $this->encodeEcPointFormat($data);
                break;
        }
    }

    /**
     * ec_point_formats(11)
     *
     * https://tools.ietf.org/html/rfc4492#section-5.1.2
     *
     * enum { uncompressed (0), ansiX962_compressed_prime (1),
     *   ansiX962_compressed_char2 (2), reserved (248..255)
     * } ECPointFormat;
     *
     * struct {
     *   ECPointFormat ec_point_format_list<1..2^8-1>
     * } ECPointFormatList;
     *
     * We ONLY support uncompressed(0)
     */
    private function encodeEcPointFormat($data)
    {
        $length = Core::_unpack('C', $data[0]);
        $data = substr($data, 1);

        for( $i = 0; $i < $length; $i++ )
        {
            $format = Core::_unpack('C', $data[$i]);
            if( $format == 0 )
            {
                $this->isUncompressed = true;
                break;
            }
        }
    }

    public function onEncodeServerHello($type, $data)
    {
        $core = $this->core;

        if( $type != TLSExtensions::TYPE_EC_POINT_FORMATS )
            return;

        $this->encodeEcPointFormat($data); 
    }

    private function decodeEcPointFormat()
    {
        // ec_point_format - uncompressed 
        $data = Core::_pack('C', 1) . Core::_pack('C', 0);

        $this->extType = TLSExtensions::TYPE_EC_POINT_FORMATS;
        $this->length  = strlen($data);

        return $this->decodeHeader() . $data;
    }

    public function onDecodeClientHello()
    {
        // ec_point_format
        $data = $this->decodeEcPointFormat();

        // elliptic curves
        $namedCurveTypes = '';

        foreach(EcDH::$typeList as $namedCurveType)
        {
            $namedCurveTypes .= Core::_pack('n', $namedCurveType);
        }

        $namedCurveData = Core::_pack('n', strlen($namedCurveTypes)) . $namedCurveTypes; 

        $this->extType = TLSExtensions::TYPE_ELLIPTIC_CURVES;
        $this->length  = strlen($namedCurveData);

        $data .= $this->decodeHeader() . $namedCurveData;       

        return $data;
    }

    public function onDecodeServerHello()
    {
        if( !$this->isEnabled() )
            return;

        return $this->decodeEcPointFormat();
    }

    public function encodeServerKeyExchange($data)
    {
        // Must turn true when onEncodeServerHello is called
        //if( !$this->isUncompressed )
        //    return;

        $core = $this->core;
        $hs = HandShakeFactory::getInstance($core, HandshakeType::SERVER_KEY_EXCHANGE);

        $data = $hs->encodeHeader($data);

        $length = $hs->get('length');

        $curveType = Core::_unpack('C', $data[0]);

        if( $curveType != 0x03 )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR),
                "Not named curve type: " + $curveType);

        $namedCurveType = Core::_unpack('n', $data[1] . $data[2] );

        if( !EcDH::isSupported($namedCurveType) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR),
                "Unknow named curve: " + $namedCurveType);

        $this->namedCurveType = $namedCurveType;

        $this->ecdh = new EcDH($this->namedCurveType);

        $publicKeyLen = Core::_unpack('C', $data[3] );
        $data = substr($data, 4);

        $publicKeyBin = substr($data, 0, $publicKeyLen);

        // Calculate and set premaster
        $this->calculatePremaster($publicKeyBin);

        // TODO verify signature
    }

    public function decodeClientKeyExchange()
    {
        $core = $this->core;
        $publicKey = $this->getSenderPublicKey();
        $data = Core::_pack('C', strlen($publicKey) ) . $publicKey;

        return $data; 
    }

    public function decodeServerKeyExchange()
    {
        $core = $this->core;
        $extensions = $core->extensions;

        $protoVersion = $core->getProtocolVersion();

        /*
         * ECCurveType
         *
         * We only support named curves, which is 0x03 
         *
         * enum { explicit_prime (1), explicit_char2 (2),
         *        named_curve (3), reserved(248..255) } ECCurveType;
         */
        $data = Core::_pack('C', 0x03);

        // Named curve type
        $data .= Core::_pack('n', $this->namedCurveType);

        // ECDH Public Key
        $this->ecdh = new EcDH($this->namedCurveType);
        $dataPublicKey = $this->ecdh->getPublicKey();

        $data .= Core::_pack('C', strlen($dataPublicKey)) . $dataPublicKey;

        /*
          * Signature
          * 
          * https://tools.ietf.org/html/rfc4492 Page 19
          * signed_params:   A hash of the params, with the signature appropriate
          * to that hash applied.  The private key corresponding to the
          * certified public key in the server's Certificate message is used
          * for signing.
          *
          * ServerKeyExchange.signed_params.sha_hash
          *    SHA(ClientHello.random + ServerHello.random +
          *                                      ServerKeyExchange.params);
         */
        $connIn  = $core->getInDuplex();
        $connOut = $core->getOutDuplex();

        $dataSign = $connIn->random . $connOut->random . $data;

        $signature = $extensions->call('SignatureAlgorithm', 'getSignature', null, $dataSign);

        if( $protoVersion >= 32 )
        {
            // Signature Hash Alogorithm
            // [null, null] never happens
            list( $hash, $sig ) = $extensions->call('SignatureAlgorithm', 'getAlgorithm', [null, null]);
            $data .= Core::_pack('C', $hash) . Core::_pack('C', $sig);
        }

        // Append signature
        $data .= Core::_pack('n', strlen($signature)) . $signature;
        
        $hs = HandShakeFactory::getInstance($core, HandshakeType::SERVER_KEY_EXCHANGE);

        $hs->setMsgType(HandshakeType::SERVER_KEY_EXCHANGE);
        $hs->set('length', strlen($data));

        return $hs->getBinHeader() . $data;
    }

    /**
     * https://tools.ietf.org/html/rfc4492#section-2
     * Called from HandshakeClientKeyExchange
     */
    public function calculatePremaster($publicKeyBin)
    {
        $ecdh = $this->ecdh;
        $sharedKey = $ecdh->calculateSharedKey($publicKeyBin);

        $this->preMaster = $sharedKey;

        return $sharedKey;
    }

    public function getPremaster()
    {
        return $this->preMaster;
    }

    public function getSenderPublicKey()
    {
        $ecdh = $this->ecdh;
        return $ecdh->getPublicKey();
    }
}


