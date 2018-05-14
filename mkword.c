/*
 * grab words (as defined by isalnum()) from text files,
 * useful for generating cracking dictionaries.
 *
 * example:
 *
 *  $ mkword *.txt | sort | uniq > words
 *
 * Bernardo Reino, aka Lepton.
 * 20021121
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>

void parse(FILE *fp) {
  enum { SEEK, WORD } state;
  int ch;

  for(state = SEEK; (ch = fgetc(fp)) != EOF; ) {
    switch(state) {
    case SEEK:
      if(isalnum(ch)) {
	ungetc(ch, fp);
	state = WORD;
      }
      break;

    case WORD:
      if(!isalnum(ch)) {
	putchar('\n');
	state = SEEK;
      } else {
	putchar(ch);
      }
      break;
    }
  }

  if(state == WORD)
    putchar('\n');
}

int main(int argc, char **argv) {
  if(argc > 1) {
    int j;

    for(j = 1; j < argc; j ++) {
      FILE *fp = fopen(argv[j], "r");

      if(fp) {
	parse(fp);
	fclose(fp);
      } else
	perror(argv[j]);
    }
  } else
    parse(stdin);

  return 0;
}
