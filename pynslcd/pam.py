
# pam.py - functions authentication, authorisation and session handling
#
# Copyright (C) 2010, 2011, 2012 Arthur de Jong
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
import socket

from ldap.filter import escape_filter_chars as escape
import ldap

import cfg
import common
import constants
import passwd


def try_bind(userdn, password):
    # open a new connection
    conn = ldap.initialize(cfg.uri)
    # bind using the specified credentials
    conn.simple_bind_s(userdn, password)
    # perform search for own object (just to do any kind of search)
    res = conn.search_s(userdn, ldap.SCOPE_BASE, '(objectClass=*)', ['dn', ])
    for entry in res:
        if entry[0] == userdn:
            return
    raise ldap.NO_SUCH_OBJECT()


class PAMRequest(common.Request):

    def validate_request(self, parameters):
        """This method checks the provided username for validity and fills
        in the DN if needed."""
        # check username for validity
        common.validate_name(parameters['username'])
        # look up user DN
        entry = passwd.uid2entry(self.conn, parameters['username'])
        if not entry:
            raise ValueError('%r: user not found' % parameters['username'])
        # save the DN
        parameters['userdn'] = entry[0]
        # get the "real" username
        value = passwd.attmap.get_rdn_value(entry[0], 'uid')
        if not value:
            # get the username from the uid attribute
            values = entry[1]['uid']
            if not values or not values[0]:
                logging.warning('%s: is missing a %s attribute', dn, passwd.attmap['uid'])
            value = values[0]
        # check the username
        if value and not common.isvalidname(value):
            raise ValueError('%s: has invalid %s attribute', dn, passwd.attmap['uid'])
        # check if the username is different and update it if needed
        if value != parameters['username']:
            logging.info('username changed from %r to %r', parameters['username'], value)
            parameters['username'] = value


class PAMAuthenticationRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_AUTHC

    def read_parameters(self, fp):
        return dict(username=fp.read_string(),
                    ignore_userdn=fp.read_string(),
                    service=fp.read_string(),
                    password=fp.read_string())
        #self.validate_request()
        # TODO: log call with parameters

    def write(self, parameters, code=constants.NSLCD_PAM_SUCCESS, msg=''):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(parameters['username'])
        self.fp.write_string('')  # userdn
        self.fp.write_int32(code)  # authc
        self.fp.write_int32(constants.NSLCD_PAM_SUCCESS)  # authz
        self.fp.write_string(msg)  # authzmsg
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self, parameters):
        # if the username is blank and rootpwmoddn is configured, try to
        # authenticate as administrator, otherwise validate request as usual
        if not parameters['username'] and cfg.rootpwmoddn:
            # authenticate as rootpwmoddn
            userdn = cfg.rootpwmoddn
            # if the caller is root we will allow the use of rootpwmodpw
            if not parameters['password'] and self.calleruid == 0 and cfg.rootpwmodpw:
                password = cfg.rootpwmodpw
            elif parameters['password']:
                password = parameters['password']
            else:
                raise ValueError('password missing')
        else:
            self.validate_request(parameters)
            userdn = parameters['userdn']
            password = parameters['password']
        # try authentication
        try:
            try_bind(userdn, password)
            logging.debug('bind successful')
            self.write(parameters)
        except ldap.INVALID_CREDENTIALS, e:
            try:
                msg = e[0]['desc']
            except:
                msg = str(e)
            logging.debug('bind failed: %s', msg)
            self.write(parameters, constants.NSLCD_PAM_AUTH_ERR, msg)


class PAMAuthorisationRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_AUTHZ

    def read_parameters(self, fp):
        return dict(username=fp.read_string(),
                    ignore_userdn=fp.read_string(),
                    service=fp.read_string(),
                    ruser=fp.read_string(),
                    rhost=fp.read_string(),
                    tty=fp.read_string())
        # TODO: log call with parameters

    def write(self, parameters, code=constants.NSLCD_PAM_SUCCESS, msg=''):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(parameters['username'])
        self.fp.write_string('')  # userdn
        self.fp.write_int32(code)
        self.fp.write_string(msg)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def check_authzsearch(self, parameters):
        if not cfg.pam_authz_search:
            return
        # escape all parameters
        variables = dict((k, escape(v)) for k, v in parameters.items())
        variables.update(
                hostname=escape(socket.gethostname()),
                fqdn=escape(socket.getfqdn()),
                dn=variables['userdn'],
                uid=variables['username'],
            )
        # go over all authz searches
        for x in cfg.pam_authz_search:
            filter = x.value(variables)
            logging.debug('trying pam_authz_search "%s"', filter)
            search = common.Search(self.conn, filter=filter, attributes=('dn', ))
            try:
                dn, values = search.items().next()
            except StopIteration:
                logging.error('pam_authz_search "%s" found no matches', filter)
                raise
            logging.debug('pam_authz_search found "%s"', dn)

    def handle_request(self, parameters):
        # fill in any missing userdn, etc.
        self.validate_request(parameters)
        # check authorisation search
        try:
            self.check_authzsearch(parameters)
        except StopIteration:
            self.write(parameters, constants.NSLCD_PAM_PERM_DENIED,
                       'LDAP authorisation check failed')
            return
        # all tests passed, return OK response
        self.write(parameters)


#NSLCD_ACTION_PAM_SESS_O
#NSLCD_ACTION_PAM_SESS_C
#NSLCD_ACTION_PAM_PWMOD
