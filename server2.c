#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 12345
#define BUFFER_SIZE 1024

char* get_time_in_timezone(const char* timezone) {
    time_t raw_time;
    struct tm *time_info;
    char *buffer = (char*)malloc(BUFFER_SIZE * sizeof(char));

    // Set timezone based on the requested timezone
    if (strcmp(timezone, "Tokyo") == 0) {
        setenv("TZ", "JST-9", 1); // Tokyo timezone
    } else if (strcmp(timezone, "New York") == 0) {
        setenv("TZ", "EST5EDT", 1); // New York timezone
    } else if (strcmp(timezone, "London") == 0) {
        setenv("TZ", "GMT0BST", 1); // London timezone
    } else if (strcmp(timezone, "Australia") == 0) {
        setenv("TZ", "Australia/Sydney", 1); // Australia timezone
    } else if (strcmp(timezone, "Africa") == 0) {
        setenv("TZ", "Africa/Cairo", 1); // Africa timezone
    }
     else if (strcmp(timezone, "India") == 0){
        setenv("TZ", "IST-5:30", 1);
     } 
     else if (strcmp(timezone, "China") == 0){
        setenv("TZ", "CST-8", 1);
     }
     else {
        setenv("TZ", timezone, 1); // Set the provided timezone
    }

    tzset(); // Update timezone

    // Get current time in the specified timezone
    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(buffer, BUFFER_SIZE, "%Y-%m-%d %H:%M:%S", time_info);

    return buffer;
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_address);
    SSL_CTX *ctx;

    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        perror("SSL context creation failed");
        exit(EXIT_FAILURE);
    }

    // Load SSL certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load SSL certificate");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        perror("Failed to load SSL private key");
        exit(EXIT_FAILURE);
    }

    // Create TCP socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 5) == -1) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Initialize buffer array with null characters
    memset(buffer, '\0', sizeof(buffer));

    // Accept incoming connections
    while (1) {
        // Accept connection
        if ((client_socket = accept(server_socket, (struct sockaddr *)&client_address, &addr_len)) == -1) {
            perror("Accept failed");
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
        if (SSL_accept(ssl) <= 0) {
            perror("TLS handshake failed");
            exit(EXIT_FAILURE);
        }

        // Receive timezone request from client
        ssize_t bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE);
        if (bytes_received <= 0) {
            perror("Receive failed");
            exit(EXIT_FAILURE);
        }
        buffer[bytes_received] = '\0'; // Null-terminate received data

        // Get current time in the requested timezone
        char* time_in_timezone = get_time_in_timezone(buffer);

        // Send current time in the specified timezone to client
        ssize_t bytes_sent = SSL_write(ssl, time_in_timezone, strlen(time_in_timezone));
        if (bytes_sent <= 0) {
            perror("Send failed");
            exit(EXIT_FAILURE);
        }

        // Free allocated memory
        free(time_in_timezone);

        // Close SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);

        // Close client socket
        close(client_socket);
    }

    // Close server socket and cleanup SSL context
    close(server_socket);
    SSL_CTX_free(ctx);

    return 0;
}
