//main1
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define AES_BLOCK_SIZE 16 // 16 bytes for AES
#define NUM_ROUNDS 10

// S-Box for AES
static const unsigned char S_BOX[256] = {
    // Fill with S-Box values from 0x00 to 0xFF
};

// Function prototypes
void *chat_peer(void *arg);
void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext);
void add_round_key(unsigned char state[4][4], const unsigned char round_key[4][4]);
void sub_bytes(unsigned char state[4][4]);
void shift_rows(unsigned char state[4][4]);
void mix_columns(unsigned char state[4][4]);
unsigned char mul2(unsigned char a);
unsigned char mul3(unsigned char a);

// Example messages for peers
const char *messages_peer1[] = {"Hello", "How are you?", "Goodbye"};
const char *messages_peer2[] = {"Hi", "I'm fine, thanks!", "See you later"};

typedef struct {
    const char **messages;
    int peer_id;
    unsigned char key[16]; // AES-128 key (16 bytes)
} peer_args;

int main() {
    pthread_t thread1, thread2;
    unsigned char key[16] = {0}; // Dummy key (replace with a real key)

    // Set up arguments for threads
    peer_args args1 = {messages_peer1, 1, {0}};
    peer_args args2 = {messages_peer2, 2, {0}};

    // Create threads for each peer
    pthread_create(&thread1, NULL, chat_peer, (void *)&args1);
    pthread_create(&thread2, NULL, chat_peer, (void *)&args2);

    // Wait for threads to finish
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}

void *chat_peer(void *arg) {
    peer_args *args = (peer_args *)arg;
    unsigned char ciphertext[AES_BLOCK_SIZE];

    for (int i = 0; args->messages[i] != NULL; i++) {
        unsigned char plaintext[AES_BLOCK_SIZE] = {0}; // Zero-initialize

        // Convert message to byte array (ASCII)
        strncpy((char *)plaintext, args->messages[i], AES_BLOCK_SIZE);

        // Encrypt the message
        aes_encrypt(plaintext, args->key, ciphertext);

        // Print the encrypted message (in hex)
        printf("Peer %d sends: ", args->peer_id);
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            printf("%02x ", ciphertext[j]);
        }
        printf("\n");
    }

    return NULL;
}

void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    unsigned char state[4][4];
    unsigned char round_key[4][4] = {0}; // Simplified, should be derived from key expansion

    // Initialize state array
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = plaintext[i * 4 + j];
        }
    }

    // Initial round key addition
    add_round_key(state, round_key);

    // Main rounds
    for (int round = 1; round < NUM_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_key);
    }

    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_key);

    // Copy state to ciphertext
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ciphertext[i * 4 + j] = state[j][i];
        }
    }
}

void add_round_key(unsigned char state[4][4], const unsigned char round_key[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= round_key[i][j];
        }
    }
}

void sub_bytes(unsigned char state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = S_BOX[state[i][j]];
        }
    }
}

void shift_rows(unsigned char state[4][4]) {
    // Shift rows for AES
    unsigned char temp;

    // Shift second row left by 1
    temp = state[1][0];
    for (int j = 0; j < 3; j++) {
        state[1][j] = state[1][j + 1];
    }
    state[1][3] = temp;

    // Shift third row left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift fourth row left by 3
    temp = state[3][3];
    for (int j = 3; j > 0; j--) {
        state[3][j] = state[3][j - 1];
    }
    state[3][0] = temp;
}

void mix_columns(unsigned char state[4][4]) {
    unsigned char temp[4];
    unsigned char a, b, c, d;

    for (int col = 0; col < 4; col++) {
        for (int i = 0; i < 4; i++) {
            temp[i] = state[i][col];
        }

        a = state[0][col];
        b = state[1][col];
        c = state[2][col];
        d = state[3][col];

        state[0][col] = (unsigned char)(mul2(a) ^ mul3(b) ^ c ^ d);
        state[1][col] = (unsigned char)(a ^ mul2(b) ^ mul3(c) ^ d);
        state[2][col] = (unsigned char)(a ^ b ^ mul2(c) ^ mul3(d));
        state[3][col] = (unsigned char)(mul3(a) ^ b ^ c ^ mul2(d));
    }
}

// Helper function for Galois Field multiplication by 2
unsigned char mul2(unsigned char a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1);
}

// Helper function for Galois Field multiplication by 3
unsigned char mul3(unsigned char a) {
    return mul2(a) ^ a;
}
