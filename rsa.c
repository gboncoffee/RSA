#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a) {
  /* Use BN_bn2hex(a) for hex string
   * Use BN_bn2dec(a) for decimal string */
  char *number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

void deriveRSAKeys(BN_CTX *ctx, const char *p, const char *q, const char *e,
                   BIGNUM *nRet, BIGNUM *privateRet, BIGNUM *publicRet) {
  BIGNUM *pminus1 = BN_new();
  BIGNUM *qminus1 = BN_new();
  BN_hex2bn(&pminus1, p);
  BN_hex2bn(&qminus1, q);

  BN_mul(nRet, pminus1, qminus1, ctx);

  BN_sub_word(pminus1, 1);
  BN_sub_word(qminus1, 1);

  BIGNUM *gcd = BN_new();
  BN_gcd(gcd, pminus1, qminus1, ctx);

  BIGNUM *totientN = BN_new();
  BN_mul(totientN, pminus1, qminus1, ctx);

  BIGNUM *lambda = BN_new();
  BN_div(lambda, NULL, totientN, gcd, ctx);

  // d = e^-1 mod lambda(n)
  BN_hex2bn(&publicRet, e);
  BN_mod_inverse(privateRet, publicRet, lambda, ctx);

  BN_free(pminus1);
  BN_free(qminus1);
  BN_free(gcd);
  BN_free(totientN);
  BN_free(lambda);
}

BIGNUM *RSAFunction(BN_CTX *ctx, BIGNUM *n, BIGNUM *key, BIGNUM *m) {
  BIGNUM *c = BN_new();
  BN_mod_exp(c, m, key, n, ctx);

  return c;
}

void task1(BN_CTX *ctx) {
  BIGNUM *n = BN_new();
  BIGNUM *privateKey = BN_new();
  BIGNUM *publicKey = BN_new();

  deriveRSAKeys(ctx, "F7E75FDC469067FFDC4E847C51F452DF",
                "E85CED54AF57E53E092113E62F436F4F", "0D88C3", n, privateKey,
                publicKey);

  printf("=== task 1 ===\n");
  printBN("Private key: ", privateKey);
  printBN("N: ", n);

  BN_free(n);
  BN_free(publicKey);
  BN_free(privateKey);
}

void task2and3and4(BN_CTX *ctx) {
  BIGNUM *n = BN_new();
  BIGNUM *publicKey = BN_new();
  BIGNUM *message = BN_new();
  BIGNUM *privateKey = BN_new();

  BN_hex2bn(&n,
            "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BN_hex2bn(&publicKey, "010001");
  BN_hex2bn(&privateKey,
            "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
  BN_hex2bn(&message, "4120746f702073656372657421"); // "A top secret!"

  printf("=== task 2 ===\n");
  BIGNUM *encrypted = RSAFunction(ctx, n, publicKey, message);
  printBN("Encrypted: ", encrypted);
  BIGNUM *verify = RSAFunction(ctx, n, privateKey, encrypted);
  printBN("Verify: ", verify);
  if (BN_cmp(verify, message) == 0) {
    printf("Does match.\n");
  } else {
    printf("Wrong!\n");
  }

  printf("=== task 3 ===\n");
  BIGNUM *encryptedMessage = BN_new();
  BN_hex2bn(&encryptedMessage,
            "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
  BIGNUM *decrypted = RSAFunction(ctx, n, privateKey, encryptedMessage);
  printBN("Decrypted: ", decrypted);

  printf("=== task 4 ===\n");
  BIGNUM *messageToSign = BN_new();
  BN_hex2bn(&messageToSign,
            "49206f776520796f752024323030302e"); // "I owe you $2000."
  BIGNUM *signedMessage = RSAFunction(ctx, n, privateKey, messageToSign);
  printBN("Signed message: ", signedMessage);
  BIGNUM *differentMessageToSign = BN_new();
  BN_hex2bn(&differentMessageToSign,
            "49206f776520796f752024333030302e"); // "I owe you $3000."
  BIGNUM *differentSignedMessage =
      RSAFunction(ctx, n, privateKey, differentMessageToSign);
  printBN("Different signed message: ", differentSignedMessage);

  BN_free(n);
  BN_free(publicKey);
  BN_free(privateKey);
  BN_free(message);
  BN_free(encrypted);
  BN_free(verify);
  BN_free(encryptedMessage);
  BN_free(decrypted);
  BN_free(messageToSign);
  BN_free(signedMessage);
  BN_free(differentMessageToSign);
  BN_free(differentSignedMessage);
}

void task5(BN_CTX *ctx) {
  BIGNUM *n = BN_new();
  BIGNUM *publicKey = BN_new();
  BIGNUM *message = BN_new();
  BIGNUM *signature = BN_new();

  BN_hex2bn(&n,
            "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
  BN_hex2bn(&publicKey, "010001");
  BN_hex2bn(&signature,
            "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
  BN_hex2bn(&message,
            "4c61756e63682061206d697373696c652e"); // "Launch a missile."

  BIGNUM *verification = RSAFunction(ctx, n, publicKey, signature);

  printf("=== task 5 ===\n");
  printBN("Verification: ", verification);
  if (BN_cmp(verification, message) == 0) {
    printf("It's legit.\n");
  } else {
    printf("Not legit.\n");
  }

  BIGNUM *corruptedSignature = BN_new();
  // Only one bit of change.
  BN_hex2bn(&corruptedSignature,
            "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
  BIGNUM *corruptedVerification =
      RSAFunction(ctx, n, publicKey, corruptedSignature);
  printBN("Verification: ", corruptedVerification);
  if (BN_cmp(corruptedVerification, message) == 0) {
    printf("It's legit.\n");
  } else {
    printf("Not legit.\n");
  }

  BN_free(n);
  BN_free(publicKey);
  BN_free(message);
  BN_free(signature);
  BN_free(corruptedSignature);
  BN_free(verification);
  BN_free(corruptedVerification);
}

int main(int argc, char *argv[]) {
  BN_CTX *ctx = BN_CTX_new();

  task1(ctx);
  task2and3and4(ctx);
  task5(ctx);

  BN_CTX_free(ctx);
}
