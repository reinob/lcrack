/* 
   Plug-in definition (don't touch it :)

   Copyright (C) Bernardo Reino (lepton@runbox.com)

   20021122
*/

#include "xtn_def.h"
#include "xtn_method.h"

struct xtn_module_t xtn_all[] = {
  { "dom", &xtn_dom_init, &xtn_dom_cmp, &xtn_dom_crypt },
  { "md4", &xtn_md4_init, &xtn_md4_cmp, &xtn_md4_crypt },
  { "md5", &xtn_md5_init, &xtn_md5_cmp, &xtn_md5_crypt },
  { "nt4", &xtn_nt4_init, &xtn_nt4_cmp, &xtn_nt4_crypt },
  { "null", &xtn_null_init, &xtn_null_cmp, &xtn_null_crypt },
  { "sha1", &xtn_sha1_init, &xtn_sha1_cmp, &xtn_sha1_crypt },
  { (char *)0, 0, 0, 0 }
};
