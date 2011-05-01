
# pam.py - functions authentication, authorisation and session handling
#
# Copyright (C) 2010, 2011 Arthur de Jong
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

import logging
import ldap

import constants
import common
import cfg
import passwd


def try_bind(userdn, password):
    # open a new connection
    conn = ldap.initialize(cfg.ldap_uri)
    # bind using the specified credentials
    conn.simple_bind_s(userdn, password)
    # perform search for own object (just to do any kind of search)
    res = conn.search_s(userdn, ldap.SCOPE_BASE, '(objectClass=*)', [ 'dn', ])
    for entry in res:
        if entry[0] == userdn:
            return
    raise ldap.NO_SUCH_OBJECT()


class PAMRequest(common.Request):

    def validate_request(self):
        """This method checks the provided username for validity and fills
        in the DN if needed."""
        from passwd import PasswdRequest
        # check username for validity
        common.validate_name(self.username)
        # look up user DN if not known
        if not self.userdn:
            entry = passwd.uid2entry(self.conn, self.username)
            if not entry:
                raise ValueError('%r: user not found' % self.username)
            # save the DN
            self.userdn = entry[0]
            # get the "real" username
            value = common.get_rdn_value(entry, passwd.PasswdRequest.attmap_passwd_uid)
            if not value:
                # get the username from the uid attribute
                values = myldap_get_values(entry, passwd.PasswdRequest.attmap_passwd_uid)
                if not values or not values[0]:
                    logging.warn('%s: is missing a %s attribute', entry.dn, passwd.PasswdRequest.attmap_passwd_uid)
                value = values[0]
            # check the username
            if value and not common.isvalidname(value):
                raise ValueError('%s: has invalid %s attribute', entry.dn, passwd.PasswdRequest.attmap_passwd_uid)
            # check if the username is different and update it if needed
            if value != self.username:
                logging.info('username changed from %r to %r', self.username, value)
                self.username = value


class PAMAuthenticationRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_AUTHC

    def read_parameters(self):
        self.username = self.fp.read_string()
        self.userdn = self.fp.read_string()
        self.servicename = self.fp.read_string()
        self.password = self.fp.read_string()
        #self.validate_request()
        # TODO: log call with parameters

    def write(self, code=constants.NSLCD_PAM_SUCCESS, msg=''):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(self.username)
        self.fp.write_string(self.userdn)
        self.fp.write_int32(code)  # authc
        self.fp.write_int32(constants.NSLCD_PAM_SUCCESS)  # authz
        self.fp.write_string(msg) # authzmsg
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self):
        # if the username is blank and rootpwmoddn is configured, try to
        # authenticate as administrator, otherwise validate request as usual
        if not self.username and cfg.rootpwmoddn:
            # authenticate as rootpwmoddn
            self.userdn = cfg.rootpwmoddn
            # if the caller is root we will allow the use of rootpwmodpw
            if not self.password and self.calleruid == 0 and cfg.rootpwmodpw:
                self.password = cfg.rootpwmodpw
        else:
            self.validate_request()
        # try authentication
        try:
            try_bind(self.userdn, self.password)
            logging.debug('bind successful')
            self.write()
        except ldap.INVALID_CREDENTIALS, e:
            try:
                msg = e[0]['desc']
            except:
                msg = str(e)
            logging.debug('bind failed: %s', msg)
            self.write(constants.NSLCD_PAM_AUTH_ERR, msg)

#class PAMAuthorisationRequest(PAMRequest):

#    action = constants.NSLCD_ACTION_PAM_AUTHZ

#    def handle_request(self):


#NSLCD_ACTION_PAM_SESS_O
#NSLCD_ACTION_PAM_SESS_C
#NSLCD_ACTION_PAM_PWMOD
