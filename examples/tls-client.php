<?php

// TLS Client

require __DIR__ . '/../vendor/autoload.php';

use PTLS\TLSContext;
use PTLS\Exceptions\TLSAlertException;

// Create a config for TLS Client
$config = TLSContext::getClientConfig([]);

// Create a TLS Engine
$tls = TLSContext::createTLS($config);

// hostname to access to
$hostname = "www.google.com";

// http headers
$httpRequest = "GET / HTTP/1.0\r\nHost: $hostname\r\n\r\n";

// Connecting to www.google.com port 443(https)
$socket = stream_socket_client("tcp://$hostname:443");

// Non-blocking mode
stream_set_blocking($socket, 0 );

// True when http request is sent out
$requestSent = false;

// Stores all http responses
$response = '';

while(true)
{
    if( !$tls->isHandshaked() )
    {
        $out = $tls->decode();

        if( strlen( $out ) > 0 )
            $w = stream_socket_sendto($socket, $out);
    }
    else
    {
        if( !$requestSent )
        {
            $out = $tls->output($httpRequest)->decode();
            stream_socket_sendto($socket, $out);
            $requestSent = true;
        }

        $response .= $tls->input();

        if( $tls->isClosed())
            break;
    }

    $read = [$socket];
    $write = $except = [];

    // Wait for a server to send data
    $n = stream_select($read, $write, $except, 60);

    // Receive raw data from a server
    $data = stream_socket_recvfrom($socket, 16384);

    if( $data == "" )
    {
        echo "Disconnted\n";
        break;
    }

    try
    {
        // Calling encode method to 
        $tls->encode($data);
    }
    catch(TLSAlertException $e)
    {

        echo "Alert: " . $e->getMessage() . "\n";

        if( strlen( $out = $e->decode() ) )
            stream_socket_sendto($socket, $out);

        break;
    }

    //echo $debug->getRecordStatus();   
}

stream_socket_shutdown( $socket, STREAM_SHUT_WR );

echo "Received content length: " . strlen($response) . "\n";
echo $response;





