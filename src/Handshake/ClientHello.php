<?php

namespace PTLS\Handshake;

use PTLS\Core;
use PTLS\Prf;
use PTLS\CipherSuites;
use PTLS\Exceptions\TLSAlertException;
use PTLS\Content\Alert;

class ClientHello extends HandshakeAbstract
{
    /**
     * For Debug
     */
    private $requestedExtensions;
    private $requestCipherIDs;

    function __construct(Core $core)
    {
        parent::__construct($core);
    }

    /**
     * Client Hello
     * https://tools.ietf.org/html/rfc5246#section-7.4.1.2
     */
    public function encode($data)
    {
        $core    = $this->core;
        $connIn = $core->getInDuplex();

        $data = $this->encodeHeader($data);

        // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
        $vMajor = $major = Core::_unpack( 'C', $data[0] );
        $vMinor = $minor = Core::_unpack( 'C', $data[1] );

        // Set TLS Version
        $core->setVersion($vMajor, $vMinor);

        // Get and set Client Random
        $random = substr( $data, 2, 32 );

        $connIn->random = $random;

        $sessionLength = Core::_unpack( 'C', $data[34] );

        $data = substr($data, 35);

        // SessionID if > 0
        if( $sessionLength > 0 )
        {
             $sessionID = substr( $data, 0, $sessionLength);
             $core->setSessionID($sessionID);
             $data = substr($data, $sessionLength);
        }

        $cipherLength = Core::_unpack( 'n', $data[0] . $data[1] );

        $data = substr($data, 2);

        $cipherIDs = [];

        // https://github.com/pornin/TestSSLServer/blob/master/Src/CipherSuite.cs
        for( $i = 0; $i < $cipherLength; $i += 2 )
        {
            // https://tools.ietf.org/html/rfc5246#section-7.4.1.2
            $cipher1 = Core::_unpack( 'C', $data[$i] );
            $cipher2 = Core::_unpack( 'C', $data[$i+1] );

            $cipherIDs[] = [$cipher1 , $cipher2];
        }

        $this->requestCipherIDs = $cipherIDs;

        $data = substr($data, $cipherLength);

        $compressionLength = Core::_unpack( 'C', $data[0]  );
        $compressionMethod = Core::_unpack( 'C', $data[1] );

        if( $compressionMethod != 0x00 )
            throw new TLSAlertException(Alert::create(Alert::HANDSHAKE_FAILURE), "compressionMethod is not null");

        $core->setCompressionMethod($compressionMethod);

        // Extensions
        $extLength = Core::_unpack( 'n', $data[2] . $data[3] );

        $data = substr( $data, 4, $extLength );

        $this->requestedExtensions = $extensions = $this->encodeExtensions($data);

        $core->extensions->onEncodeClientHello($extensions);

        $cipherID = CipherSuites::pickCipherID($core, $cipherIDs);

        if( is_null( $cipherID ) )
            throw new TLSAlertException(Alert::create(Alert::INTERNAL_ERROR), "Cipher Suite not found");

        $core->cipherSuite = new CipherSuites($cipherID);
    }

    public function decode()
    {
        $core = $this->core;
        $connOut = $core->getOutDuplex();
       
        list($vMajor, $vMinor) = $core->getVersion();
 
        // Set client random
        $connOut->random = Core::getRandom(32);
 
        // Set TLS Version
        $data = Core::_pack('C', $vMajor ) . Core::_pack('C', $vMinor);

        // Client Random
        $data .= $connOut->random;

        // Session ID - no session
        $data .= Core::_pack('C', 0x00);

        // Cipher Suite
        $cipherSuiteList = CipherSuites::decodeCipherList();

        $data .= Core::_pack('n', strlen($cipherSuiteList) ) . $cipherSuiteList;

        // Compression method
        $data .= Core::_pack('C', 0x01 ) . Core::_pack('C', $core->getCompressionMethod());

        // Extension Length
        //$data .= Core::_pack('n', 0x00);
        $extensionData = $core->extensions->onDecodeClientHello();
        $data .= Core::_pack('n', strlen($extensionData)) . $extensionData;

        $this->msgType = HandshakeType::CLIENT_HELLO;
        $this->length = strlen($data);
        return $this->getBinHeader() . $data;
    }

    public function debugInfo()
    {
        /*
         * struct {
         *  ProtocolVersion client_version;
         *  Random random;
         *  SessionID session_id;
         *  CipherSuite cipher_suites<2..2^16-2>;
         *  CompressionMethod compression_methods<1..2^8-1>;
         *  select (extensions_present) {
         *      case false:
         *          struct {};
         *      case true:
         *          Extension extensions<0..2^16-1>;
         *  };
         * } ClientHello;
         */
        $core = $this->core;
        $connIn = $this->core->getInDuplex();

        $protoVersion = $core->getProtocolVersion();
        $sessionID    = base64_encode($core->getSessionID());
        $compressionMethod = $core->getCompressionMethod();

        $cipherSuites = [];

        // [$cipher1 , $cipher2]
        foreach( $this->requestCipherIDs as $value )
        {
            $cipherSuites[] = "0x" . dechex($value[0]) . dechex($value[1]);
        }

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
             . "Session ID:       $sessionID \n"
             . "[CipherSuites]\n"
             . implode("\n", $cipherSuites) . "\n"
             . "[Extensions]\n"
             . implode("\n", $extensions);
    }

}






