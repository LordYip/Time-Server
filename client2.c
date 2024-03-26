#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define PORT 12345
#define BUFFER_SIZE 1024

int main() {
    int client_socket;
    struct sockaddr_in server_address;
    char buffer[BUFFER_SIZE];
    SSL_CTX *ctx;

    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        perror("SSL context creation failed");
        exit(EXIT_FAILURE);
    }

    // Create TCP socket
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_address.sin_port = htons(PORT);

    // Connect to server
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // Create new SSL structure for the connection
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        perror("SSL structure creation failed");
        exit(EXIT_FAILURE);
    }

    // Assign the socket to the SSL structure
    SSL_set_fd(ssl, client_socket);

    // Perform TLS handshake
    if (SSL_connect(ssl) <= 0) {
        perror("TLS handshake failed");
        exit(EXIT_FAILURE);
    }

    


    // Request timezone input from user
    char timezone[BUFFER_SIZE];

    // Initialize timezone array with null characters
    memset(timezone, '\0', sizeof(timezone));
    
    printf("Enter timezone (e.g., 'Tokyo', 'New York', 'London'): ");
    fgets(timezone, BUFFER_SIZE, stdin);
    timezone[strcspn(timezone, "\n")] = '\0'; // Remove newline character

    // Send timezone request to server
    if (SSL_write(ssl, timezone, strlen(timezone)) <= 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    // Receive and display time from server
    ssize_t bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE);
    if (bytes_received <= 0) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }
    buffer[bytes_received] = '\0'; // Null-terminate received data
    printf("Received current time from server: %s\n", buffer);

    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // Close socket
    close(client_socket);

    return 0;
}
