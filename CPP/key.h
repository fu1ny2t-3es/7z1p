#define MAGIC_KEY "0"

static inline void CRYPT_IN(uint8_t buf[32]) { buf[0] = buf[0]; }
static inline void CRYPT_OUT(uint8_t buf[32]) { buf[0] = buf[0]; }
