<?php

namespace PTLS\Handshake;

use PTLS\Core;
use PTLS\CipherSuites;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class ServerHello extends HandshakeAbstract
{
    /**
     * For Debug
     */
    private $requestedExtensions;

    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    public function encode($data)
    {
        $core  = $this->core;
        $connIn = $core->getInDuplex();

        $data = $this->encodeHeader($data);

        $vMajor = Core::_unpack('C', $data[0] );
        $vMinor = Core::_unpack('C', $data[1] ); 

        // Server Random
        $random = substr( $data, 2, 32 );

        $connIn->random = $random; 

        // Session ID
        $sessionLength = Core::_unpack( 'C', $data[34] );

        $data = substr($data, 35);

        // SessionID if > 0
        if( $sessionLength > 0 )
        {
             $sessionID = substr( $data, 35, $sessionLength);
             $core->setSessionID($sessionID);
             $data = substr($data, $sessionLength);
        }

        $cipherID = [Core::_unpack('C', $data[0] ), Core::_unpack('C', $data[1] )];

        $cipherSuite = new CipherSuites($cipherID);

        if( is_null($cipherSuite ) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "cipherSuite is null");

        $core->cipherSuite = $cipherSuite;

        // Cipher Suite
        $core->setCompressionMethod(Core::_unpack( 'C', $data[2] ));

        // Extensions
        if( strlen($data) < 5 )
            return;

        $extLength = Core::_unpack( 'n', $data[3] . $data[4] );
        $data = substr( $data, 5, $extLength );

        $this->requestedExtensions = $extensions = $this->encodeExtensions($data);

        $core->extensions->onEncodeServerHello($extensions);

    }

    public function decode()
    {
        $core  = $this->core;

        $extensions = $core->extensions;
        $connOut    = $core->getOutDuplex();
        $sessionID  = $core->getSessionID();

        list($vMajor, $vMinor) = $core->getVersion();

        // Set server random
        $connOut->random = Core::getRandom(32);

        $sessionLength = strlen($sessionID);

        $data = Core::_pack('C', $vMajor)
              . Core::_pack('C', $vMinor)
              . $connOut->random
              . Core::_pack('C', $sessionLength );

        if( $sessionLength > 0 )
        {
            $data .= $sessionID;
        }

        $cipherSuite = $core->cipherSuite;
        list( $cipher1, $cipher2 ) = $cipherSuite->getID();

        $data .= Core::_pack('C', $cipher1 ) 
               . Core::_pack('C', $cipher2 ); 

        // Compression method length 
        $data .= Core::_pack('C', 0x00);

        $extData = $extensions->onDecodeServerHello();

        if( strlen($extData) > 0 )
            $data .= Core::_pack('n', strlen($extData) ) . $extData;

        $this->msgType = 2;
        $this->length = strlen($data);

        return $this->getBinHeader() . $data;
    }

    public function debugInfo()
    {
        /*
         * struct {
         *    ProtocolVersion server_version;
         *    Random random;
         *    SessionID session_id;
         *    CipherSuite cipher_suite;
         *    CompressionMethod compression_method;
         *    select (extensions_present) {
         *        case false:
         *            struct {};
         *        case true:
         *            Extension extensions<0..2^16-1>;
         *    };
         * } ServerHello;
         */
        $core = $this->core;        
        $connIn = $this->core->getInDuplex();

        $protoVersion = $core->getProtocolVersion();
        $sessionID    = base64_encode($core->getSessionID());
        $cipherSuite  = $core->cipherSuite->debugInfo();

        $extensions = [];

        // ['type' => $extType, 'data' => $extData]
        foreach( $this->requestedExtensions as $value )
        {
            $extensions[]= "Type: " . dechex($value['type'])
                         . ' Data Length: ' . strlen($value['data'] );
        }

        return "[HandshakeType::ServerHello]\n"
             . "Lengh:            " . $this->length . "\n"
             . "Protocol Version: $protoVersion \n"
             . "Session ID:       $sessionID\n"
             . "[Extensions]\n" 
             . implode("\n", $extensions) . "\n"
             . $cipherSuite;
    }
}





