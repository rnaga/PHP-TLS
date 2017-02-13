<?php

// TLS HTTPS Server

require __DIR__ . '/../vendor/autoload.php';

use PTLS\TLSContext;
use PTLS\Exceptions\TLSAlertException;


// TLS Config
/*
// RSA
$config = TLSContext::getServerConfig([
    'key_pair_files' => [
       'cert' => ['pem/crt.pem'],
       'key'  => ['pem/key.pem', 'test']
    ]
]);
*/

// ECDSA
$config = TLSContext::getServerConfig([
    'key_pair_files' => [
       'cert' => ['pem/ecdsa_crt.pem'],
       'key'  => ['pem/ecdsa_key.pem', '']
    ]
]);


$tlsClients = [];

// Create a tcp server socket
$server = stream_socket_server("tcp://0.0.0.0:443", $errno, $errstr);

// Non-blocking mode
stream_set_blocking( $server, 0 );

$sockets = [$server];

$index = 1;

$closeSocket = function($clientSocket){
    global $sockets, $tlsClients;

    list($tls, $index) = $tlsClients[(int)$clientSocket];
    unset( $tlsClients[(int)$clientSocket] );
    unset( $sockets[$index] );
    stream_socket_shutdown( $clientSocket, STREAM_SHUT_WR );
};

while(1)
{
    $readSockets = array_values($sockets);
    $write = $except = null;

    echo "Waiting...\n";
    $n = stream_select( $readSockets, $write, $except, 60);

    if( $n > 0 )
    {
        foreach( $readSockets as $readSocket )
        {
            if( $server === $readSocket )
            {
                // Accept a new client
                $clientSocket = stream_socket_accept( $server );

                echo "Accept: $clientSocket\n";

                // Non-blocking mode
                stream_set_blocking( $clientSocket, 0 );

                // Create a TLS Engine
                $tls = TLSContext::createTLS($config);

                // Store it to an array 
                $tlsClients[(int)$clientSocket] = [$tls, $index];

                $sockets[$index++] = $clientSocket;
            }
            else
            {
                $clientSocket = $readSocket;

                // Get the TLS Engine
                list($tls, $index) = $tlsClients[(int)$clientSocket];

                // Receive raw data from a client
                $data = stream_socket_recvfrom($clientSocket, 16384); 

                if( 0 >= strlen($data) )
                {
                    echo "Disconnted\n";
                    $closeSocket($clientSocket);
                    break;
                }

                try
                {
                    $tls->encode($data);
                }
                catch(TLSAlertException $e)
                {
                    echo "Alert: " . $e->getMessage() . "\n";

                    if( strlen($out = $e->decode()) )
                        stream_socket_sendto($clientSocket, $out);
                }

                // Get any buffer from TLS Engine and send it to the client
                if( strlen($out = $tls->decode()) )
                    stream_socket_sendto($clientSocket, $out);

                // Handshake is done, start sending/receiving own data
                if( $tls->isHandshaked() )
                {
                    echo "Finished handshaking for $clientSocket\n";

                    $in = $tls->input();

                    $content = file_get_contents('html/index.html');

                    $response = "HTTP/2.0 200 OK\r\nContent-Length: " . strlen($content) . "\r\n\r\n"
                              . $content;

                    $out = $tls->output($response)->decode();
                    stream_socket_sendto($clientSocket, $out);
                    $closeSocket($clientSocket);
                }
            }
        }
    }
}


