#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>

#define AES_BLOCK_SIZE 16 // 16 bytes for AES
#define NUM_ROUNDS 10
#define MAX_MESSAGE_SIZE 256
#define KEY_PATH "/tmp/aes_key"
#define PROJ_ID 65

// S-Box for AES
static const unsigned char S_BOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round Constant (RCON) array
static const unsigned char RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// Function prototypes
void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext);
void aes_decrypt(const unsigned char *ciphertext, const unsigned char *key, unsigned char *plaintext);
void add_round_key(unsigned char state[4][4], const unsigned char *round_key);
void sub_bytes(unsigned char state[4][4]);
void inv_sub_bytes(unsigned char state[4][4]);
void shift_rows(unsigned char state[4][4]);
void inv_shift_rows(unsigned char state[4][4]);
void mix_columns(unsigned char state[4][4]);
void inv_mix_columns(unsigned char state[4][4]);
void key_expansion(const unsigned char *key, unsigned char *expanded_key);
unsigned char mul2(unsigned char a);
unsigned char mul3(unsigned char a);
unsigned char mul9(unsigned char a);
unsigned char mul11(unsigned char a);
unsigned char mul13(unsigned char a);
unsigned char mul14(unsigned char a);

typedef struct {
    long mtype;
    char mtext[MAX_MESSAGE_SIZE];
} message_t;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <peer_id>\n", argv[0]);
        exit(1);
    }

    int peer_id = atoi(argv[1]);
    key_t key = ftok(KEY_PATH, PROJ_ID);
    int msgid = msgget(key, 0666 | IPC_CREAT);

    if (msgid == -1) {
        perror("msgget");
        exit(1);
    }

    unsigned char aes_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    unsigned char plaintext[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE];
    message_t msg;

    while (1) {
        printf("Enter message (or 'quit' to exit): ");
        fgets(msg.mtext, MAX_MESSAGE_SIZE, stdin);
        msg.mtext[strcspn(msg.mtext, "\n")] = 0;

        if (strcmp(msg.mtext, "quit") == 0) {
            break;
        }

        msg.mtype = 3 - peer_id;  // Send to the other peer

        // Encrypt the message
        memset(plaintext, 0, AES_BLOCK_SIZE);
        strncpy((char *)plaintext, msg.mtext, AES_BLOCK_SIZE);
        aes_encrypt(plaintext, aes_key, ciphertext);

        // Convert ciphertext to hex string
        char hex_ciphertext[AES_BLOCK_SIZE * 2 + 1];
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            sprintf(&hex_ciphertext[i*2], "%02x", ciphertext[i]);
        }
        strcpy(msg.mtext, hex_ciphertext);

        if (msgsnd(msgid, &msg, strlen(msg.mtext) + 1, 0) == -1) {
            perror("msgsnd");
            exit(1);
        }
        printf("Sent: %s\n", msg.mtext);
        // Receive message
        if (msgrcv(msgid, &msg, MAX_MESSAGE_SIZE, peer_id, 0) == -1) {
            perror("msgrcv");
            exit(1);
        }

        printf("Received: %s\n", msg.mtext);
        // Decrypt the received message
        unsigned char received_ciphertext[AES_BLOCK_SIZE];
        unsigned char decrypted_text[AES_BLOCK_SIZE + 1];
        
        // Convert hex string to bytes
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            sscanf(&msg.mtext[i*2], "%2hhx", &received_ciphertext[i]);
        }
        
        // Decrypt the message
        aes_decrypt(received_ciphertext, aes_key, decrypted_text);
        
        // Null-terminate the decrypted text
        decrypted_text[AES_BLOCK_SIZE] = '\0';
        
        printf("Decrypted: %s\n", decrypted_text);
    }

    if (msgctl(msgid, IPC_RMID, NULL) == -1) {
        perror("msgctl");
        exit(1);
    }

    return 0;
}

void aes_encrypt(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    unsigned char state[4][4];
    unsigned char expanded_key[176];

    // Key expansion
    key_expansion(key, expanded_key);

    // Initialize state array
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = plaintext[i * 4 + j];
        }
    }

    // Initial round key addition
    add_round_key(state, expanded_key);

    // Main rounds
    for (int round = 1; round < NUM_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, expanded_key + round * 16);
    }

    // Final round (no MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, expanded_key + NUM_ROUNDS * 16);

    // Copy state to ciphertext
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ciphertext[i * 4 + j] = state[j][i];
        }
    }
}

void aes_decrypt(const unsigned char *ciphertext, const unsigned char *key, unsigned char *plaintext) {
    unsigned char state[4][4];
    unsigned char expanded_key[176];

    // Key expansion
    key_expansion(key, expanded_key);

    // Initialize state array
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = ciphertext[i * 4 + j];
        }
    }

    // Initial round key addition
    add_round_key(state, expanded_key + NUM_ROUNDS * 16);

    // Main rounds
    for (int round = NUM_ROUNDS - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, expanded_key + round * 16);
        inv_mix_columns(state);
    }

    // Final round (no InvMixColumns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expanded_key);

    // Copy state to plaintext
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            plaintext[i * 4 + j] = state[j][i];
        }
    }
}

void add_round_key(unsigned char state[4][4], const unsigned char *round_key) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= round_key[i + 4 * j];
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

void inv_sub_bytes(unsigned char state[4][4]) {
    static const unsigned char INV_S_BOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = INV_S_BOX[state[i][j]];
        }
    }
}

void shift_rows(unsigned char state[4][4]) {
    unsigned char temp;

    // Row 1: Shift left by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: Shift left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Shift left by 3 (equivalent to right by 1)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void inv_shift_rows(unsigned char state[4][4]) {
    unsigned char temp;

    // Row 1: Shift right by 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Row 2: Shift right by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Shift right by 3 (equivalent to left by 1)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void mix_columns(unsigned char state[4][4]) {
    unsigned char temp[4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[j] = state[j][i];
        }
        state[0][i] = mul2(temp[0]) ^ mul3(temp[1]) ^ temp[2] ^ temp[3];
        state[1][i] = temp[0] ^ mul2(temp[1]) ^ mul3(temp[2]) ^ temp[3];
        state[2][i] = temp[0] ^ temp[1] ^ mul2(temp[2]) ^ mul3(temp[3]);
        state[3][i] = mul3(temp[0]) ^ temp[1] ^ temp[2] ^ mul2(temp[3]);
    }
}

void inv_mix_columns(unsigned char state[4][4]) {
    unsigned char temp[4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[j] = state[j][i];
        }
        state[0][i] = mul14(temp[0]) ^ mul11(temp[1]) ^ mul13(temp[2]) ^ mul9(temp[3]);
        state[1][i] = mul9(temp[0]) ^ mul14(temp[1]) ^ mul11(temp[2]) ^ mul13(temp[3]);
        state[2][i] = mul13(temp[0]) ^ mul9(temp[1]) ^ mul14(temp[2]) ^ mul11(temp[3]);
        state[3][i] = mul11(temp[0]) ^ mul13(temp[1]) ^ mul9(temp[2]) ^ mul14(temp[3]);
    }
}

void key_expansion(const unsigned char *key, unsigned char *expanded_key) {
    unsigned char temp[4];
    int i = 0;

    // Copy the initial key to the first 16 bytes of expanded key
    for (i = 0; i < 16; i++) {
        expanded_key[i] = key[i];
    }

    i = 1;
    while (i < 11) {  // 11 round keys for AES-128
        // Copy the last 4 bytes of the previous expanded key
        for (int j = 0; j < 4; j++) {
            temp[j] = expanded_key[(i - 1) * 16 + 12 + j];
        }

        // Perform key schedule core
        if (i % 1 == 0) {
            // Rotate word
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubBytes
            for (int j = 0; j < 4; j++) {
                temp[j] = S_BOX[temp[j]];
            }

            // XOR with round constant
            temp[0] ^= RCON[i];
        }

        // XOR with previous round key and add to expanded key
        for (int j = 0; j < 16; j++) {
            expanded_key[i * 16 + j] = expanded_key[(i - 1) * 16 + j] ^ temp[j % 4];
        }

        i++;
    }
}

unsigned char mul2(unsigned char a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1);
}

unsigned char mul3(unsigned char a) {
    return mul2(a) ^ a;
}

unsigned char mul9(unsigned char a) {
    return mul2(mul2(mul2(a))) ^ a;
}

unsigned char mul11(unsigned char a) {
    return mul2(mul2(mul2(a))) ^ mul2(a) ^ a;
}

unsigned char mul13(unsigned char a) {
    return mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ a;
}

unsigned char mul14(unsigned char a) {
    return mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ mul2(a);
}
