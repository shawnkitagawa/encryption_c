#include <netdb.h>      // gethostbyname()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> // send(),recv()
#include <sys/types.h>  // ssize_t
#include <unistd.h>
#include <ctype.h>

#define MAX_BUFFER_SIZE 70000  

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void printErrorAndExit(const char *msg, int exitCode) {
    fprintf(stderr, "%s\n", msg);
    exit(exitCode);
}

void readFileToBuffer(const char* filename, char* buffer, size_t bufferSize) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        exit(1);
    }

    size_t bytesRead = fread(buffer, sizeof(char), bufferSize - 1, file);
    if (bytesRead == 0 && ferror(file)) {
        fprintf(stderr, "Error reading file %s\n", filename);
        fclose(file);
        exit(1);
    }

    buffer[bytesRead] = '\0';

    if (bytesRead > 0 && buffer[bytesRead - 1] == '\n') {
        buffer[bytesRead - 1] = '\0';
    }

    fclose(file);
}

int validateText(const char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && (text[i] < 'A' || text[i] > 'Z')) {
            return 0;
        }
    }
    return 1;
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname) {
    memset((char*)address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct hostent* hostInfo = gethostbyname(hostname);
    if (hostInfo == NULL) {
        fprintf(stderr, "CLIENT: ERROR, no such host\n");
        exit(2);
    }

    memcpy((char*)&address->sin_addr.s_addr,
           hostInfo->h_addr_list[0],
           hostInfo->h_length);
}

int main(int argc, char *argv[]) {
    int socketFD, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    char plaintextBuffer[MAX_BUFFER_SIZE];
    char keyBuffer[MAX_BUFFER_SIZE];
    char buffer[MAX_BUFFER_SIZE];

    // Check usage & args
    if (argc != 4) {
        fprintf(stderr, "USAGE: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    // Read plaintext and key files
    readFileToBuffer(argv[1], plaintextBuffer, sizeof(plaintextBuffer));
    readFileToBuffer(argv[2], keyBuffer, sizeof(keyBuffer));

    // Validate plaintext and key characters
    if (!validateText(plaintextBuffer)) {
        fprintf(stderr, "Error: plaintext contains invalid characters\n");
        exit(1);
    }
    if (!validateText(keyBuffer)) {
        fprintf(stderr, "Error: key contains invalid characters\n");
        exit(1);
    }

    // Check that key is at least as long as plaintext
    if (strlen(keyBuffer) < strlen(plaintextBuffer)) {
        fprintf(stderr, "Error: key is too short\n");
        exit(1);
    }

    // Create a socket
    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        error("CLIENT: ERROR opening socket");
    }

    // Set up the server address struct
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");

    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        fprintf(stderr, "Error: could not contact otp_enc_d on port %s\n", argv[3]);
        close(socketFD);
        exit(2);
    }

    // Send client ID to server ("enc_client") and wait for confirmation
    memset(buffer, '\0', sizeof(buffer));
    strcpy(buffer, "enc_client");
    charsWritten = send(socketFD, buffer, strlen(buffer), 0);
    if (charsWritten < 0) {
        error("CLIENT: ERROR writing to socket");
    }

    // Receive server response 
    memset(buffer, '\0', sizeof(buffer));
    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (charsRead < 0) {
        error("CLIENT: ERROR reading from socket");
    }

    if (strcmp(buffer, "enc_server") != 0) {
        fprintf(stderr, "Error: connected to wrong server type on port %s\n", argv[3]);
        close(socketFD);
        exit(2);
    }

    // Send plaintext
    memset(buffer, '\0', sizeof(buffer));
    strcpy(buffer, plaintextBuffer);
    charsWritten = send(socketFD, buffer, strlen(buffer), 0);
    if (charsWritten < 0) {
        error("CLIENT: ERROR writing plaintext to socket");
    }

    // Send key
    memset(buffer, '\0', sizeof(buffer));
    strcpy(buffer, keyBuffer);
    charsWritten = send(socketFD, buffer, strlen(buffer), 0);
    if (charsWritten < 0) {
        error("CLIENT: ERROR writing key to socket");
    }

    memset(buffer, '\0', sizeof(buffer));

    charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
    if (charsRead < 0) {
        error("CLIENT: ERROR reading from socket");
    }

    // Make sure it's null-terminated exactly at charsRead
    buffer[charsRead] = '\0';

    // Print only what was received
    printf("%s", buffer);


    
    close(socketFD);

    return 0;
}
