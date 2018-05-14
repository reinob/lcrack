/*
 * mktbl - generate pre-computed domino-hash table from a words file
 *
 * usage: cat words | ./mktbl -m <alg> <output>
 *
 * output file = { { word[0..15], hash[0..15] } ... }
 *
 * Bernardo Reino, aka Lepton.
 * 20021127
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "xtn_def.h"
#include "xtn_method.h"
#include "global.h"

xtn_crypt_t xtn_crypt;

struct elem {
  char word[16];
  char hash[16];
};

BYTE K_ASCII[BYTE_MAX];

void mktbl(FILE *fp) {
  CODE_BLOCK_PTR R;
  struct elem next;

  while(1) {
    char *ptr;

    memset(next.word, '\0', 16);
    if(! fgets(next.word, 16, stdin))
      break;

    if((ptr = strrchr(next.word, '\r')) != NULL) *ptr = '\0';
    if((ptr = strrchr(next.word, '\n')) != NULL) *ptr = '\0';

    R = xtn_crypt(next.word, strlen(next.word), K_ASCII);
    memcpy(next.hash, R, 16);

    fwrite(&next, sizeof(next), 1, fp);
  }
}

void usage(int e, char *me) {
  FILE *f = e ? stderr : stdout;
  struct xtn_module_t *xtn_ptr;

  fprintf(f, "usage: %s [-h] -m <method> <file>\n", me);
  fprintf(f, " <method> = { ");

  for(xtn_ptr = &xtn_all[0]; xtn_ptr->xtn_text; xtn_ptr = xtn_ptr ++) {
    fprintf(f, "'%s' ", xtn_ptr->xtn_text);
  }

  fprintf(f, "}\n");
  exit(e);
}

int main(int argc, char *argv[]) {
  char *alg = NULL;
  char *ofile = NULL;
  FILE *fp;

  struct xtn_module_t *xtn_ptr;
  int j;

  for(j = 1; j < argc; j ++) {
    if(!strcmp(argv[j], "-h")) {
      usage(0, argv[0]);
    }
    else if(!strcmp(argv[j], "-m")) {
      alg = argv[++ j];
    }
    else if(ofile == NULL) {
      ofile = argv[j];
    }
    else
      usage(1, argv[0]);
  }

  if(alg == NULL)
    usage(1, argv[0]);

  for(xtn_ptr = &xtn_all[0]; xtn_ptr->xtn_text; xtn_ptr = xtn_ptr ++) {
    if(!strcmp(alg, xtn_ptr->xtn_text)) {
      xtn_ptr->xtn_init();
      xtn_crypt = xtn_ptr->xtn_function;
    }
  }

  if(xtn_crypt == NULL)
    usage(2, argv[0]);

  for(j = 0; j < sizeof(K_ASCII); j ++)
    K_ASCII[j] = j;

  fp = fopen(ofile, "wb");

  if(fp) {
    mktbl(fp);
    fclose(fp);
  } else {
    perror(ofile);
    exit(3);
  }

  return 0;
}
