/* 
 * Cracking Engine
 * Copyright (C) Bernardo Reino (aka Lepton) (lepton@runbox.com)
 * 20021120

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 */

#include "global.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

void KEY_text(BYTE *stream, char *dst, unsigned int len) {
  while(len --)
    *(dst ++) = K_CHARSET[(int)*(stream ++)];
}

/*
 * Check if Hash(K) matches a Hash from the Password List
 */

int KEY_find(char *K, int K_Len, CODE_BLOCK_PTR H) {
  PasswordElement *ptr;
  BYTE mod_index;
  unsigned int found;

  found = 0;
  PasswordCount ++;

  mod_index = H[0] & 0xff;
  
  for(ptr = PasswordList[mod_index].next; ptr; ptr = ptr->next)
    if(*ptr->login && xtn_cmp(H, ptr->data)) {
      if(verbose) {
	fprintf(stderr, "found: login(%s), passwd(", ptr->login);
	print_key(stderr, K, K_Len);
	fprintf(stderr, ")\n");
      }

      if(pot_file || !verbose) {
	fprintf(pot, "%s:", ptr->login);
	print_key(pot, K, K_Len);
	fprintf(pot, "\n");
      }

      ptr->login[0] = '\0'; /* mark login as cracked.. */
      PasswordLeft --;
      found ++;
      //return 1;
    }

  return found;
}

void KEY_zero(BYTE *K, unsigned int Len) {
  while(Len --)
    *(K ++) = 0;
}

signed int KEY_next(BYTE *K, unsigned int Len) {
  signed int j = Len - 1;

  while(j >= 0) {
    if(++ K[j] >= K_CHARSET_LEN) {
      K[j --] = 0;
    } else
      break;
  }

  return j;
}

void KEY_rand(BYTE *K, unsigned int Len) {
  unsigned int j;

  for(j = 0; j < Len; j ++) {
    K[j] = rand() % K_CHARSET_LEN;
  }
}

/*
 * compute hash(passwd) and search in the list..
 */

int KEY_cmp(char *passwd, int len) {
  CODE_BLOCK_PTR R;

  R = xtn_crypt(passwd, len, K_ACTIVE);
  
  return KEY_find(passwd, len, R);
}

int KEY_word(char *passwd, int len, int xtd) {
  static char sym_tbl[] = " 0123456789^!\"$%&/()=?'`+-*{}[]#.,;:_-~<>|@";
  static int sym_len = sizeof(sym_tbl);
  
  char aux[MAX_PASS_LEN+1];
  int j;

  strncpy(aux, passwd, MAX_PASS_LEN);
  aux[MAX_PASS_LEN] = '\0';

  if(KEY_cmp(aux, len))
    return 1;

  for(j = 0; j < len; j ++)
    aux[j] = tolower(aux[j]);

  if(KEY_cmp(aux, len))
    return 1;

  aux[0] = toupper(aux[0]);

  if(KEY_cmp(aux, len))
    return 1;

  for(j = 0; j < len; j ++)
    aux[j] = toupper(aux[j]);

  if(KEY_cmp(aux, len))
    return 1;

  if((xtd) && (len < MAX_PASS_LEN - 1)) {
    int i;

    strncpy(aux, passwd, MAX_PASS_LEN);
    aux[MAX_PASS_LEN] = '\0';

    /* prefix symbol */

    aux[len + 1] = '\0';

    for(i = 0; i < sym_len; i ++) {
      aux[len] = sym_tbl[i];
      if(KEY_word(aux, len+1, 0)) /* recursive */
	return 1;
    }

    /* suffix symbol */

    memcpy(aux + 1, passwd, len);

    for(i = 0; i < sym_len; i ++) {
      aux[0] = sym_tbl[i];
      if(KEY_word(aux, len+1, 0)) /* recursive */
	return 1;
    }
  }

  return 0;
}

int KEY_login(char *passwd, int len, int xtd) {
  static char sym_tbl[] = "0123456789^!\"$%&/()=?'`+-*{}[]#.,;:_-~<>|@";
  static int sym_len = sizeof(sym_tbl);
  
  char aux[MAX_PASS_LEN+1];
  int j;

  strncpy(aux, passwd, MAX_PASS_LEN);
  aux[MAX_PASS_LEN] = '\0';

  if(KEY_cmp(aux, len))
    return 1;

  for(j = 0; j < len; j ++)
    aux[j] = tolower(aux[j]);

  if(KEY_cmp(aux, len))
    return 1;

  aux[0] = toupper(aux[0]);

  if(KEY_cmp(aux, len))
    return 1;

  for(j = 0; j < len; j ++)
    aux[j] = toupper(aux[j]);

  if(KEY_cmp(aux, len))
    return 1;

  if((xtd) && (len < MAX_PASS_LEN - 1)) {
    int i;

    /* prefix symbol */

    aux[len + 1] = '\0';

    for(i = 0; i < sym_len; i ++) {
      aux[len] = sym_tbl[i];
      if(KEY_login(aux, len+1, 0))
	return 1;
    }

    /* suffix symbol */

    memcpy(aux + 1, passwd, len);

    for(i = 0; i < sym_len; i ++) {
      aux[0] = sym_tbl[i];
      if(KEY_login(aux, len+1, 0))
	return 1;
    }
  }

  if((xtd) && (2*len < MAX_PASS_LEN - 1)) {
    /* double login */

    strcpy(aux, passwd);
    strcat(aux, passwd);

    if(KEY_login(aux, 2*len, 0))
      return 1;
  }

  return 0;
}
