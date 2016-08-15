<?php

// TLS Echo Server

/**
 * -------------------------------------------------------------------------
 *  Use the command below for a client
 * -------------------------------------------------------------------------
 *
 * TLSv1.1
 * openssl s_client -status -tls1_1 -state -status -msg -connect 0.0.0.0:443
 *
 * TLSv1.2
 * openssl s_client -status -tls1_2 -state -status -msg -connect 0.0.0.0:443
 *
 * -------------------------------------------------------------------------
 * Commands used to create crt and private key for this example
 * -------------------------------------------------------------------------
 *
 * openssl genrsa -out key.pem 2048
 * openssl req -new -sha256 -key key.pem -out csr.csr
 * openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out crt.pem
 */

require __DIR__ . '/../vendor/autoload.php';

use PTLS\TLSContext;
use PTLS\Exceptions\TLSAlertException;


// TLS Config
$config = TLSContext::getServerConfig([
    'key_pair_files' => [
       'cert' => ['pem/crt.pem'],
       'key'  => ['pem/key.pem', 'test']
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
                    // Convert TLS data
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
                    // Receive data from a client
                    $in = $tls->input();

                    echo "received from $clientSocket: $in";

                    // Conver output into TLS format
                    $out = $tls->output($in)->decode();
                    stream_socket_sendto($clientSocket, $out);
                }
            }
        }
    }
}


