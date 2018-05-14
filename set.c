/* 
   Cracking Engine,

     LoadExternalSpec()
     LoadCharSet()
     LoadLenSet()
     LoadRegEx()

   Copyright (C) Bernardo Reino (lepton@runbox.com)
   20040912

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/

/*
 * K_CHARSET = Vector of characters included in brute-force keyspace
 * K_CHARSET_LEN = Length of vector
 *
 * K_LENSET = Vector of password-lengths to try
 * K_LENSET_LEN = Length of vector
 */

#include <stdio.h>                /* [f]printf() */
#include <string.h>               /* memset() */
#include <stdlib.h>               /* strtoul() */
#include <ctype.h>                /* isspace() */

#include "global.h"

static unsigned char *fix_expr(const unsigned char *expr,
			       int *len) {
  enum { NORMAL, ESCAPE, OCTAL, DECIMAL, HEXA } state;
  const unsigned char *rptr;
  unsigned char *fixed, *wptr;
  int prefix;
  unsigned int val = 0;

  wptr = fixed = strdup(expr); /* may waste some space, but.. */

  for(state = NORMAL, rptr = expr; *rptr; rptr ++) {
    int ch = *rptr;

    switch(state) {
    case NORMAL:
      if(ch == '\\') { /* escaped character */
	state = ESCAPE;
      } else {
	*(wptr ++) = ch;
      }
      break;

    case ESCAPE:
      if(ch == '0') { /* octal */
	prefix = ch;
	val = 0;
	state = OCTAL;
      }
      else if(isdigit(ch)) { /* decimal */
	prefix = ch;
	val = 0;
	state = DECIMAL;
	rptr --;
      }
      else if((ch == 'x') || (ch == 'X')) { /* hexa */
	prefix = ch;
	val = 0;
	state = HEXA;
      }
      else { /* nothing special (or a backslash) */
	*(wptr ++) = ch;
	state = NORMAL;
      }

      break;

    case OCTAL:
      if((ch >= '0') || (ch <= '7')) {
	int nval;

	nval = (val * 8) + (unsigned int)(ch - '0');
	if(nval < BYTE_MAX)
	  val = nval;
	else
	  goto end_octal;
      } else { /* end of octal */
      end_octal:
	*(wptr ++) = (unsigned char)val;
	rptr --;
	state = NORMAL;
      }
      break;

    case DECIMAL:
      if(isdigit(ch)) {
	int nval;

	nval = (val * 10) + (unsigned int)(ch - '0');
	if(nval < BYTE_MAX)
	  val = nval;
	else
	  goto end_decimal;
      } else { /* end of decimal */
      end_decimal:
	*(wptr ++) = (unsigned char)val;
	rptr --;
	state = NORMAL;
      }
      break;

    case HEXA:
      if(isxdigit(ch)) {
	int nval;

	nval = val * 16;

	if((ch >= '0') && (ch <= '9'))
	  nval += (ch - '0');
	else if((ch >= 'A') && (ch <= 'F'))
	  nval += (ch - 'A' + 10);
	else if((ch >= 'a') && (ch <= 'f'))
	  nval += (ch - 'a' + 10);

	if(nval < BYTE_MAX)
	  val = nval;
	else
	  goto end_hexa;
      } else { /* end of decimal */
      end_hexa:
	*(wptr ++) = (unsigned char)val;
	rptr --;
	state = NORMAL;
      }
      break;
    }
  }

  switch(state) {
  case NORMAL: /* OK */
    break;

  case ESCAPE: /* expr ended with escape char.. */
    if("add it anyway..")
      *(wptr ++) = '\\';

    break;

  case OCTAL:
  case DECIMAL:
  case HEXA: /* don't forget me! :) */
    *(wptr ++) = (unsigned char)val;
    break;
  }

  *wptr = '\0';
  if(len)
    *len = (int)(wptr - fixed);
  return fixed;
}

static FILE *ExternalFile(const char *me, const char *default_filename) {
  char *file = NULL;
  char *where_am_i, *ptr;
  int do_bin = 0;
  FILE *fp;

  where_am_i = strdup(me);
  ptr = strrchr(where_am_i, '/');
  if(ptr) {
    *ptr = '\0';
    do_bin = 1;
  }

  file = strdup(default_filename);
  fp = fopen(file, "r");

  if(fp == NULL) {
    free(file), file = NULL;

    if(do_bin) {
      file = malloc(strlen(where_am_i) + strlen(default_filename) + 2);
      sprintf(file, "%s/%s", where_am_i, default_filename);

      fp = fopen(file, "r");
    }

    if(fp == NULL) {
      char *home = getenv("HOME");

      if(file)
	free(file), file = NULL;

      if(home) {
	file = malloc(strlen(home) + strlen(default_filename) + 2);
	sprintf(file, "%s/%s", home, default_filename);

	fp = fopen(file, "r");
      }

      if(fp == NULL) {
	if(file)
	  free(file), file = NULL;

	file = malloc(strlen(default_filename) + 6);
	sprintf(file, "/etc/%s", default_filename);

	fp = fopen(file, "r");
      }
    }
  }

  if(file)
    free(file);

  return fp;
}

unsigned char *LoadExternalSpec(const char *me, const char *file, 
				const char *spec) {
  FILE *external;
  unsigned char *value = NULL;

  if((external = ExternalFile(me, file)) != NULL) {
    unsigned char line[1024];

    while(fgets(line, 1024, external)) {
      unsigned char *ptr, *begin;

      ptr = strrchr(line, '\n'); if(ptr) *ptr = '\0';
      ptr = strrchr(line, '\r'); if(ptr) *ptr = '\0';

      for(begin = &line[0]; *begin && isspace(*begin); begin ++) ;

      if(*begin) {
	if(*begin == '#')
	  continue;

	ptr = strstr(begin, " = ");
	if(ptr) {
	  unsigned char *def;

	  for(def = ptr + 3; *def && isspace(*def); def ++) ;
	  while((ptr > begin) && isspace(*ptr)) *(ptr --) = '\0';

	  if(strcmp(spec, begin) == 0) {
	    if(*def) {
	      ptr = def + strlen(def) - 1;
	      while((ptr > def) && isspace(*ptr)) ptr --;
	      if(isspace(*ptr)) *ptr = '\0';
	    }

	    value = strdup(def);
	  }
	} else {
	  /* ignore line.. */
	}
      }
    }

    fclose(external);
  } else
    fprintf(stderr, "%s: no %s config file found..\n", me, file);

  /* fprintf(stderr, "(dbg) %s = '%s'\n", spec, value); */
  return value;
}

int LoadCharSet(const unsigned char *set) {
  unsigned char *fixed_set;
  int cmap[BYTE_MAX], stored, stored_len, next;
  int fixed_len, ndx;
  enum { SEEK, NEXT, CSET } state;

  fixed_set = fix_expr(set, &fixed_len);
  memset(cmap, 0, sizeof(cmap));
  stored = 0;

  for(state = SEEK, ndx = 0; ndx < fixed_len; ndx ++) {
    next = fixed_set[ndx];

    switch(state) {
    case SEEK:
      stored = next;
      state = NEXT;
      break;

    case NEXT:
      if(next == '-') {
	state = CSET;
      } else {
	cmap[stored] ++;
	stored = next;
      }
      break;

    case CSET:
      if(next == '-') { /* double '-', weird.. */
	fprintf(stderr, 
		"alert: specified character set might not be "
		"what you are thinking of! :)\n");
	cmap[stored] ++;
	stored = next;
      } else {
	int j;

	for(j = stored; j <= next; j ++)
	  cmap[j] ++;

	state = SEEK;
      }
      break;
    }
  }

  free(fixed_set); /* not needed anymore.. */

  switch(state) {
  case CSET:
    fprintf(stderr, "failed: character set not closed (%c-?)\n", stored);
    return -1;

  case NEXT:
    cmap[stored] ++; /* don't forget me! */
    break;

  case SEEK:
    break;
  }

  for(stored_len = stored = next = 0; next < BYTE_MAX; next ++) {
    if(cmap[next] > 1) {
      fprintf(stderr, 
	      "alert: character '%c' repeated %d times in set, fixing..\n",
	      next, cmap[next]);
      cmap[next] = 1;
    }

    if(cmap[next] > 0) {
      K_CHARSET[stored ++] = next;
      stored_len += isprint(next) ? 1 : 4;
    }

    K_SYMBOL[next] = (BYTE)cmap[next];
  }

  K_CHARSET_LEN = stored;

  if(verbose) {
    int printed_len, one_line, limit;

    for(limit = stored_len; limit > 70; )
      limit = (limit + 1)/2;

    fprintf(stderr, "loaded: CSET[%d] = {", K_CHARSET_LEN);

    if(stored_len < 50) {
      one_line = 1;
      fputc(' ', stderr);
    } else {
      one_line = 0;
      fputc('\n', stderr);
    }

    for(printed_len = next = 0; next < stored; next ++) {
      int ch;

      if((printed_len == 0) && !one_line)
	fprintf(stderr, "  ");

      ch = K_CHARSET[next];
      if(isprint(ch))
	fputc(ch, stderr), printed_len ++;
      else
	fprintf(stderr, "\\x%02x", ch), printed_len += 4;

      if(printed_len > limit)
	fprintf(stderr, "\n"), printed_len = 0;
    }

    if(printed_len)
      fputc(one_line ? ' ' : '\n', stderr);
    
    fprintf(stderr, "}\n");
  }
  
  return 0;
}

int LoadLenSet(const char *set) {
  int lmap[16];
  int stored = 0, next;
  int in_set = 0, eol = 0;

  memset(lmap, 0, sizeof(lmap));

  while((! eol) && *set) {
    char *endptr;
    size_t seg_len;

    seg_len = strspn(set, "x0123456789");
    if(seg_len) {
      next = strtoul(set, &endptr, 0);

      if(endptr != (set + seg_len))
	goto bad_format;

      if((next < 1) || (next > MAX_PASS_LEN)) {
	fprintf(stderr, "failed: size of password must be < %d\n", 
		MAX_PASS_LEN);
	return -1;
      }

      set = endptr;

      switch(*set) {
      case '\0':
      case ',':
	if(in_set) {
	  int j;

	  for(j = stored; j <= next; j ++)
	    lmap[j - 1] ++;

	  in_set = 0;
	} else {
	  lmap[next - 1] ++;
	}

	if(! *set)
	  eol = 1;
	else
	  set ++;
	break;

      case '-':
	if(in_set) 
	  goto bad_format;

	stored = next;
	in_set = 1;
	set ++;
	break;

      default:
	fprintf(stderr, 
		"failed: invalid character ('%c') found in length-set\n", 
		*set);
	return -1;
      }
    } else {
    bad_format:
      fprintf(stderr, "failed: bad length-set format\n");
      return -1;
    }
  }

  for(stored = next = 0; next < 16; next ++) {
    if(lmap[next] > 1) {
      fprintf(stderr, "alert: length(%d) specified %u times\n",
	      next, lmap[next]);
    }

    if(lmap[next])
      K_LENSET[stored ++] = next + 1;
  }

  K_LENSET_LEN = stored;

  if(verbose) {
    fprintf(stderr, "loaded: LSET[%d] = { ", K_LENSET_LEN);

    for(next = 0; next < stored; next ++) {
      fprintf(stderr, "%d ", K_LENSET[next]);
    }
    fprintf(stderr, "}\n");
  }

  return 0;
}

static struct regex_t *rx_add(struct regex_t *rx, int wild, 
			      const BYTE *symbol) {
  struct regex_t *tail;

  tail = malloc(sizeof(struct regex_t));
  tail->next = NULL;
  tail->wild = wild;

  memcpy(tail->symbol, symbol, BYTE_MAX * sizeof(BYTE));

  rx->next = tail;
  return tail;
}

static struct regex_t *rx_parse(const unsigned char *regex, int len) {
  static BYTE symbol[BYTE_MAX];

  enum { SEEK, SYMBOL, SET, START, RANGE } state;
  struct regex_t *rx, *tail;
  unsigned char left = '\0';
  int s_len = 0, wild = 0, ndx;

  rx = malloc(sizeof(struct regex_t));
  rx->next = NULL;
  tail = rx;

  for(state = SEEK, ndx = 0; ndx < len; ) {
    switch(state) {
    case SEEK:
      memset(symbol, 0, sizeof(symbol));

      switch(regex[ndx]) {
      case '[':
        state = SET;
        s_len = 0;
        ndx ++;
        break;

      default:
        state = SYMBOL;
      }
      break;

    case SYMBOL:
      symbol[(int) regex[ndx ++]] ++;

      RXMinLength ++;
      tail = rx_add(tail, 0, symbol);
      state = SEEK;
      break;

    case SET:
      switch(regex[ndx]) {
      case ']':
        if(s_len == 0) { /* use default character set */
          memcpy(symbol, K_SYMBOL, sizeof(symbol));
	  RXMinLength ++;
        }
	else if((s_len == 1) && (left == '*')) {
	  /* special case, [*] = variable-length wildcard  */
	  memcpy(symbol, K_SYMBOL, sizeof(symbol));
	  RXWildCount ++;
	  wild = 1;
	}

        tail = rx_add(tail, wild, symbol);
	wild = 0;
        state = SEEK;
        break;

      default:
        left = regex[ndx];
        state = START;
        break;
      }

      ndx ++;
      break;

    case START:
      switch(regex[ndx]) {
      case ']':
        symbol[(int)left] ++;
        s_len ++;
        state = SET;
        break;

      case '-':
        state = RANGE;
        ndx ++;
        break;

      default:
        symbol[(int)left] ++;
        s_len ++;
        left = regex[ndx ++];
        break;
      }
      break;

    case RANGE:
      if(left > regex[ndx]) {
        fprintf(stderr, "(dbg) empty set [%c-%c], will take it as '%c'\n",
                left, regex[ndx], left);

        symbol[(int)left] ++;
        s_len ++;
      } else {
        while(left <= regex[ndx]) {
          symbol[(int)(left ++)] ++;
          s_len ++;
        }
      }

      ndx ++;
      state = SET;
      break;
    }
  }

  switch(state) {
  case SEEK: /* OK */
    break;

  case SYMBOL:
  case SET:
  case START:
  case RANGE:
    return NULL;
  }

  tail = rx->next;
  free(rx);

  return tail;
}

static void rx_dump(FILE *o, struct regex_t *rx) {
  while(rx) {
    int j;

    fprintf(o, "[");

    if(rx->wild)
      fputc('*', o);
    else {
      for(j = 0; j < BYTE_MAX; j ++)
	if(rx->symbol[j] > 0) {
	  if(isprint(j))
	    fputc(j, o);
	  else
	    fprintf(o, "\\x%02x", j);
	}
    }

    fprintf(o, "]");

    rx = rx->next;
  }
}

int LoadRegEx(const unsigned char *regex) {
  struct regex_t *rx;
  unsigned char *fixed;
  int fixed_len;

  if(verbose) {
    fprintf(stderr, "(dbg) regex '%s'\n", regex);
  }

  fixed = fix_expr(regex, &fixed_len);
  rx = rx_parse(fixed, fixed_len);
  free(fixed);

  if(rx == NULL)
    return -1;

  K_REGEX = rx;

  if(verbose) {
    fprintf(stderr, "loaded: REGEX = ");
    rx_dump(stderr, rx);
    fprintf(stderr, "\n");
  }

  return 0;
}
