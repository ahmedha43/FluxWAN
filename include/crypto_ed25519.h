#ifndef CRYPTO_ED25519_H
#define CRYPTO_ED25519_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 */
void crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* SHA-512 */
void crypto_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

/* Ed25519 Public Key Signature Verification
 * Returns 1 if valid, 0 if invalid */
int crypto_ed25519_verify(const uint8_t signature[64],
                          const uint8_t *message, size_t message_len,
                          const uint8_t public_key[32]);

/* Curve25519 Scalarmult (RFC 7748 / WireGuard) */
int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p);
int crypto_scalarmult_base(uint8_t *q, const uint8_t *n);

/* URL-safe Base64 Encoding and Decoding */
int crypto_base64_encode(const uint8_t *src, size_t len, char *dst, size_t dst_max);
int crypto_base64_decode(const char *src, uint8_t *dst, size_t dst_max, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ED25519_H */
