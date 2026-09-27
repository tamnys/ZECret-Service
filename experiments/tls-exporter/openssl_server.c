// Local interoperability fixture. It sends only ephemeral test exporter bytes
// over the same loopback TLS connection; it is not a production TLS server.
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char label[] = "EXPERIMENTAL-zrpc-attestation-v1";

static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *outlen, const unsigned char *in,
                       unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    if (inlen != 9 || in[0] != 8 || memcmp(in + 1, "http/1.1", 8) != 0)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = in + 1;
    *outlen = 8;
    return SSL_TLSEXT_ERR_OK;
}

static int send_all(SSL *ssl, const unsigned char *bytes, size_t length) {
    while (length != 0) {
        size_t written = 0;
        if (SSL_write_ex(ssl, bytes, length, &written) != 1 || written == 0)
            return 0;
        bytes += written;
        length -= written;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4)
        return 2;
    char *end = NULL;
    errno = 0;
    long fd = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || fd < 0 || fd > INT_MAX)
        return 2;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        return 3;
    int ok = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
             SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
             SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_ASN1) == 1 &&
             SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) == 1 &&
             SSL_CTX_check_private_key(ctx) == 1;
    if (!ok) {
        SSL_CTX_free(ctx);
        return 3;
    }
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    int client = accept((int)fd, NULL, NULL);
    if (client < 0) {
        SSL_CTX_free(ctx);
        return 4;
    }
    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, client) != 1 || SSL_accept(ssl) != 1 ||
        SSL_version(ssl) != TLS1_3_VERSION) {
        SSL_free(ssl);
        close(client);
        SSL_CTX_free(ctx);
        return 5;
    }
    unsigned char nonce[32], other_nonce[32], outputs[128];
    for (size_t i = 0; i < sizeof(nonce); i++)
        nonce[i] = (unsigned char)i;
    memcpy(other_nonce, nonce, sizeof(nonce));
    other_nonce[0] ^= 1;
    ok = SSL_export_keying_material(ssl, outputs, 64, label,
                                    sizeof(label) - 1, nonce, sizeof(nonce), 1) == 1 &&
         SSL_export_keying_material(ssl, outputs + 64, 64, label,
                                    sizeof(label) - 1, other_nonce,
                                    sizeof(other_nonce), 1) == 1 &&
         send_all(ssl, outputs, sizeof(outputs));
    OPENSSL_cleanse(outputs, sizeof(outputs));
    SSL_free(ssl);
    close(client);
    SSL_CTX_free(ctx);
    return ok ? 0 : 6;
}
