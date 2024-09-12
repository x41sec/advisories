#include <CkHttp.h>
#include <iostream>
#include <CkSocket.h>
#include <CkCertStore.h>
#include <CkCert.h>

#include <CkSocket.h>
#include <CkCert.h>

void clientauth(void)
    {
    // This example requires the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    CkSocket listenSslSocket;

    // An SSL/TLS server needs a digital certificate.  This example loads it from a PFX file.
    // Note: This is the server's certificate.

    CkCert cert;
    // The 1st argument is the file path, the 2nd arg is the
    // PFX file's password:
    bool success = cert.LoadPfxFile("cert.pfx","");
    if (success != true) {
        std::cout << cert.lastErrorText() << "\r\n";
        return;
    }

    // To accept client client certificates in the TLS handshake,
    // we must indicate a list of acceptable client certificate root CA DN's
    // that are allowed.  (DN is an acronym for Distinguished Name.)
    // Call AddSslAcceptableClientCaDn once for each acceptable CA DN.
    // Here are a few examples so you can see the general format of a DN.
    //listenSslSocket.AddSslAcceptableClientCaDn("C=XX, ST=clientstate, L=clientcity, O=clientcompany, OU=clientasdf, CN=clienthostname");
    //listenSslSocket.AddSslAcceptableClientCaDn("O=Digital Signature Trust Co., CN=DST Root CA X3");

    // Use the certificate:
    success = listenSslSocket.InitSslServer(cert);
    if (success != true) {
        std::cout << listenSslSocket.lastErrorText() << "\r\n";
        return;
    }

    // Bind and listen on a port:
    int myPort = 8123;
    // Allow for a max of 5 queued connect requests.
    int backLog = 5;
    success = listenSslSocket.BindAndListen(myPort,backLog);
    if (success != true) {
        std::cout << listenSslSocket.lastErrorText() << "\r\n";
        return;
    }
    std::cout << "listening" << std::endl;

    // If accepting an SSL/TLS connection, the SSL handshake is part of the connection
    // establishment process. This involves a few back-and-forth messages between the
    // client and server to establish algorithms and a shared key to create the secure
    // channel. The sending and receiving of these messages are governed by the
    // MaxReadIdleMs and MaxSendIdleMs properties. If these properties are set to 0
    // (and this is the default unless changed by your application), then the
    // AcceptNextConnection can hang indefinitely during the SSL handshake process.
    // Make sure these properties are set to appropriate values before calling AcceptNextConnection.

    // Set a 10 second max for waiting to read/write.  This is for the SSL/TLS handshake establishment.
    listenSslSocket.put_MaxReadIdleMs(10000);
    listenSslSocket.put_MaxSendIdleMs(10000);

    // Accept a single client connection and establish the secure SSL/TLS channel:
    CkSocket *clientSock = 0;
    int maxWaitMillisec = 20000;
    clientSock = listenSslSocket.AcceptNextConnection(maxWaitMillisec);
    if (listenSslSocket.get_LastMethodSuccess() == false) {
        std::cout << listenSslSocket.lastErrorText() << "\r\n";
        return;
    }

    // The client (in this example) is going to send a "Hello Server! -EOM-"
    // message.  Read it:
    const char *receivedMsg = clientSock->receiveUntilMatch("-EOM-");
    if (clientSock->get_LastMethodSuccess() != true) {
        std::cout << clientSock->lastErrorText() << "\r\n";
        return;
    }

    std::cout << receivedMsg << "\r\n";

    // Send a "Hello Client! -EOM-" message:
    success = clientSock->SendString("Hello Client! -EOM-");
    if (success != true) {
        std::cout << clientSock->lastErrorText() << "\r\n";
        return;
    }

    // Close the connection with the client
    // Wait a max of 20 seconds (20000 millsec)
    success = clientSock->Close(20000);

    delete clientSock;
    }

int main(void)
    {
clientauth();
    }
