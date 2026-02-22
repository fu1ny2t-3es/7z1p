#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* --- OS-Specific Configurations for Randomness --- */
#if defined(_WIN32) || defined(_WIN64)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <unistd.h>
    #include <fcntl.h>
#endif

// Completely safe from system collisions because of the 'MEP_' prefix
#define CHA_PACK_LE_BYTES_TO_U32(a) \
    (((uint32_t)((a)[0]))       | \
     ((uint32_t)((a)[1]) <<  8) | \
     ((uint32_t)((a)[2]) << 16) | \
     ((uint32_t)((a)[3]) << 24))

/* --- ChaCha20 Macros --- */
#define CHACHA_ROTL(v, c) (((v) << (c)) | ((v) >> (32 - (c))))

#define CHACHA_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = CHACHA_ROTL(d, 16); \
    c += d; b ^= c; b = CHACHA_ROTL(b, 12); \
    a += b; d ^= a; d = CHACHA_ROTL(d,  8); \
    c += d; b ^= c; b = CHACHA_ROTL(b,  7);

/* Internal helper: marked static so it stays hidden inside each C file */
static void chacha20_block(uint32_t *out, const uint32_t *key, uint32_t counter, const uint8_t *nonce) {
    uint32_t state[16];
    uint32_t initial[16];
    int i;

    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    memcpy(&state[4], key, 32);
    state[12] = counter;
    memcpy(&state[13], nonce, 12);

    memcpy(initial, state, 64);

    for (i = 0; i < 20; i += 2) {
        CHACHA_QUARTERROUND(state[0], state[4], state[8],  state[12]);
        CHACHA_QUARTERROUND(state[1], state[5], state[9],  state[13]);
        CHACHA_QUARTERROUND(state[2], state[6], state[10], state[14]);
        CHACHA_QUARTERROUND(state[3], state[7], state[11], state[15]);
        
        CHACHA_QUARTERROUND(state[0], state[5], state[10], state[15]);
        CHACHA_QUARTERROUND(state[1], state[6], state[11], state[12]);
        CHACHA_QUARTERROUND(state[2], state[7], state[8],  state[13]);
        CHACHA_QUARTERROUND(state[3], state[4], state[9],  state[14]);
    }

    for (i = 0; i < 16; i++) {
        out[i] = state[i] + initial[i];
    }
}

/* API 1: Safe to include everywhere */
static inline int get_secure_random(uint8_t *buffer, size_t length) {
#if defined(_WIN32) || defined(_WIN64)
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    
    size_t total_read = 0;
    while (total_read < length) {
        ssize_t bytes_read = read(fd, buffer + total_read, length - total_read);
        if (bytes_read <= 0) {
            close(fd);
            return -1;
        }
        total_read += (size_t)bytes_read;
    }
    close(fd);
    return 0;
#endif
}

/* API 2: Safe to include everywhere */
static inline void chacha20_crypt(const uint8_t *key, const uint8_t *nonce, uint32_t counter, uint8_t *data, size_t data_len) {
    uint32_t key_words[8];
    uint32_t keystream_words[16];
    uint8_t *keystream = (uint8_t*)keystream_words;
    size_t i;

    memcpy(key_words, key, 32);

    while (data_len > 0) {
        chacha20_block(keystream_words, key_words, counter, nonce);
        counter++;

        size_t chunk = (data_len > 64) ? 64 : data_len;
        for (i = 0; i < chunk; i++) {
            data[i] ^= keystream[i];
        }

        data += chunk;
        data_len -= chunk;
    }
}

#endif /* SIMPLE_CRYPTO_H */
