#include <openssl/bn.h>
#include <openssl/types.h>
#include <stdio.h>
#include <stdlib.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a) {
  /* Use BN_bn2hex(a) for hex string
   * Use BN_bn2dec(a) for decimal string */
  char *number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

int main() {
  char *s = malloc(NBITS * sizeof(char));
  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();

  BIGNUM *e = BN_new();
  BIGNUM *d = BN_new();
  BIGNUM *n = BN_new();

  BIGNUM *lambda = BN_new();

  BIGNUM *psub1 = BN_new();
  BIGNUM *qsub1 = BN_new();

  BIGNUM *mulsub = BN_new();
  BIGNUM *pqgcd = BN_new();

  BIGNUM *minus1 = BN_new();

  BIGNUM *m = BN_new();
  BIGNUM *c = BN_new();
  BIGNUM *decrypted = BN_new();

  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  BN_mul(n, p, q, ctx);

  BN_hex2bn(&psub1, "F7E75FDC469067FFDC4E847C51F452DE");
  BN_hex2bn(&qsub1, "E85CED54AF57E53E092113E62F436F4E");

  BN_gcd(pqgcd, psub1, qsub1, ctx);
  BN_mul(mulsub, psub1, qsub1, ctx);
  BN_div(lambda, NULL, mulsub, pqgcd, ctx);

  // d = e^-1 mod lambda(n)
  BN_mod_inverse(d, e, lambda, ctx);

  scanf("%s", s);
  BN_hex2bn(&m, s);

  // c = m^e mod n
  BN_mod_exp(c, m, e, n, ctx);

  printBN("M = ", m);
  printBN("Encrypted Message = ", c);

  // decrypted = c^d mod n
  BN_mod_exp(decrypted, c, d, n, ctx);
  printBN("Decrypted Message = ", decrypted);

  BN_free(decrypted);
  BN_free(c);
  BN_free(m);
  BN_free(mulsub);
  BN_free(pqgcd);
  BN_free(minus1);
  BN_free(qsub1);
  BN_free(psub1);
  BN_free(lambda);
  BN_free(n);
  BN_free(d);
  BN_free(e);
  BN_free(q);
  BN_free(p);

  BN_CTX_free(ctx);
  free(s);
}