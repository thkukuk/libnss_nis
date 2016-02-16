/* Copyright (C) 1996-2014 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _NSS_NIS6_H
#define _NSS_NIS6_H	1

#include <nss.h>
#include <sys/types.h>
#include <rpcsvc/ypclnt.h>

#define NSS_FLAG_NETID_AUTHORITATIVE    1
#define NSS_FLAG_SERVICES_AUTHORITATIVE 2
#define NSS_FLAG_SETENT_BATCH_READ      4
#define NSS_FLAG_ADJUNCT_AS_SHADOW      8

/* lookup_actions, service_library and service_user are
   from glibc nsswitch.h header file. */

/* Actions performed after lookup finished.  */
typedef enum
{
  NSS_ACTION_CONTINUE,
  NSS_ACTION_RETURN
} lookup_actions;


typedef struct service_library
{
  /* Name of service (`files', `dns', `nis', ...).  */
  const char *name;
  /* Pointer to the loaded shared library.  */
  void *lib_handle;
  /* And the link to the next entry.  */
  struct service_library *next;
} service_library;

typedef struct service_user
{
  /* And the link to the next entry.  */
  struct service_user *next;
  /* Action according to result.  */
  lookup_actions actions[5];
  /* Link to the underlying library object.  */
  service_library *library;
  /* Collection of known functions.  */
  void *known;
  /* Name of the service (`files', `dns', `nis', ...).  */
  char name[0];
} service_user;

/* Get current set of default flags.  */
extern int _nsl_default_nss (void);

/* Convert YP error number to NSS error number.  */
extern const enum nss_status __yperr2nss_tab[];
extern const unsigned int __yperr2nss_count;

static inline enum nss_status
yperr2nss (int errval)
{
  if ((unsigned int) errval >= __yperr2nss_count)
    return NSS_STATUS_UNAVAIL;
  return __yperr2nss_tab[(unsigned int) errval];
}


struct response_t
{
  struct response_t *next;
  size_t size;
  char mem[0];
};

typedef struct intern_t
{
  struct response_t *start;
  struct response_t *next;
  size_t offset;
} intern_t;


extern int _nis_saveit (int instatus, char *inkey, int inkeylen, char *inval,
			 int invallen, char *indata);


#endif /* nss-nis.h */
