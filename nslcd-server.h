/*
   nslcd-server.h - server socket routines

   Copyright (C) 2006 West Consulting
   Copyright (C) 2006 Arthur de Jong

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
   MA 02110-1301 USA
*/

#ifndef _NSLCD_SERVER_H
#define _NSLCD_SERVER_H 1

#include "nslcd.h"
#include "nslcd-common.h"

/* returns a socket ready to answer requests from the client,
   return <0 on error */
int nslcd_server_open(void);

/* create a strem from the client socket, read a request message
   and pass the stream to one of the functions below.
   returns <0 in case of errors, this function closes the socket */
void nslcd_server_handlerequest(int sock);

/* LDAP methods */
/* TODO: these definitions should probably be moved */

int nslcd_alias_byname(FILE *fp);
int nslcd_alias_all(FILE *fp);
int nslcd_ether_byname(FILE *fp);
int nslcd_ether_byether(FILE *fp);
int nslcd_ether_all(FILE *fp);
int nslcd_group_byname(FILE *fp);
int nslcd_group_bygid(FILE *fp);
int nslcd_group_bymember(FILE *fp);
int nslcd_group_all(FILE *fp);
int nslcd_host_byname(FILE *fp);
int nslcd_host_byaddr(FILE *fp);
int nslcd_host_all(FILE *fp);
int nslcd_netgroup_byname(FILE *fp);
int nslcd_network_byname(FILE *fp);
int nslcd_network_byaddr(FILE *fp);
int nslcd_network_all(FILE *fp);
int nslcd_passwd_byname(FILE *fp);
int nslcd_passwd_byuid(FILE *fp);
int nslcd_passwd_all(FILE *fp);
int nslcd_protocol_byname(FILE *fp);
int nslcd_protocol_bynumber(FILE *fp);
int nslcd_protocol_all(FILE *fp);
int nslcd_rpc_byname(FILE *fp);
int nslcd_rpc_bynumber(FILE *fp);
int nslcd_rpc_all(FILE *fp);
int nslcd_service_byname(FILE *fp);
int nslcd_service_bynumber(FILE *fp);
int nslcd_service_all(FILE *fp);
int nslcd_shadow_byname(FILE *fp);
int nslcd_shadow_all(FILE *fp);

#endif /* not _NSLCD_SERVER_H */
