/*
 * This program generates an ed25519 private key and a self-signed
 * x509 certificate and writes them to stdout and stderr seperately.
 *
 *
 * 2023-7-16 Kerry
 */

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

#define SERIAL_MAX_BYTES 20

#include <stdio.h>

int main() {
  gnutls_x509_privkey_t key;
  gnutls_x509_crt_t cert;

  {
    // key generation
    gnutls_x509_privkey_init(&key);
    gnutls_x509_privkey_generate(key, GNUTLS_PK_EDDSA_ED25519, 0, 0);

    // output
    gnutls_datum_t keyout;
    gnutls_x509_privkey_export2_pkcs8(key, GNUTLS_X509_FMT_PEM, 0, 0, &keyout);

    fwrite(keyout.data, keyout.size, 1, stdout);
    gnutls_free(keyout.data);
  }

  {
    // certificate generation
    gnutls_x509_crt_init(&cert);

    gnutls_x509_crt_set_version(cert, 3);

    unsigned char serial[SERIAL_MAX_BYTES];
    gnutls_rnd(GNUTLS_RND_NONCE, serial, SERIAL_MAX_BYTES);
    serial[0] &= 0x7F;
    gnutls_x509_crt_set_serial(cert, serial, SERIAL_MAX_BYTES);

    gnutls_x509_crt_set_key(cert, key);

    gnutls_x509_crt_set_activation_time(cert, 0);
    gnutls_x509_crt_set_expiration_time(cert, -1);

    gnutls_x509_crt_sign(cert, cert, key);

    // certificate output
    gnutls_datum_t certout;
    gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_PEM, &certout);

    fwrite(certout.data, certout.size, 1, stderr);
    gnutls_free(certout.data);
  }

  return 0;
}
