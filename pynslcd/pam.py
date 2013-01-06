
# pam.py - functions authentication, authorisation and session handling
#
# Copyright (C) 2010, 2011, 2012, 2013 Arthur de Jong
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

from ldap.controls.ppolicy import PasswordPolicyControl, PasswordPolicyError
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
    pwctrl = PasswordPolicyControl()
    res, data, msgid, ctrls = conn.simple_bind_s(userdn, password, serverctrls=[pwctrl])
    # go over bind result server controls
    for ctrl in ctrls:
        if ctrl.controlType == PasswordPolicyControl.controlType:
            # found a password policy control
            logging.debug('PasswordPolicyControl found: error=%s (%s), timeBeforeExpiration=%s, graceAuthNsRemaining=%s',
                'None' if ctrl.error is None else PasswordPolicyError(ctrl.error).prettyPrint(),
                ctrl.error, ctrl.timeBeforeExpiration, ctrl.graceAuthNsRemaining)
            if ctrl.error == 0:  # passwordExpired
                return constants.NSLCD_PAM_AUTHTOK_EXPIRED, PasswordPolicyError(ctrl.error).prettyPrint()
            elif ctrl.error == 1:  # accountLocked
                return constants.NSLCD_PAM_ACCT_EXPIRED, PasswordPolicyError(ctrl.error).prettyPrint()
            elif ctrl.error == 2:  # changeAfterReset
                return constants.NSLCD_PAM_NEW_AUTHTOK_REQD, 'Password change is needed after reset'
            elif ctrl.error:
                return constants.NSLCD_PAM_PERM_DENIED, PasswordPolicyError(ctrl.error).prettyPrint()
            elif ctrl.timeBeforeExpiration is not None:
                return constants.NSLCD_PAM_NEW_AUTHTOK_REQD, 'Password will expire in %d seconds' % ctrl.timeBeforeExpiration
            elif ctrl.graceAuthNsRemaining is not None:
                return constants.NSLCD_PAM_NEW_AUTHTOK_REQD, 'Password expired, %d grace logins left' % ctrl.graceAuthNsRemaining
    # perform search for own object (just to do any kind of search)
    results = conn.search_s(userdn, ldap.SCOPE_BASE, '(objectClass=*)', ['dn', ])
    for entry in results:
        if entry[0] == userdn:
            return constants.NSLCD_PAM_SUCCESS, ''
    # if our DN wasn't found raise an error to signal bind failure
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
            # FIXME: we should close the stream with an empty response here
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
                    service=fp.read_string(),
                    ruser=fp.read_string(),
                    rhost=fp.read_string(),
                    tty=fp.read_string(),
                    password=fp.read_string())
        #self.validate_request()
        # TODO: log call with parameters

    def write(self, username, authc=constants.NSLCD_PAM_SUCCESS,
              authz=constants.NSLCD_PAM_SUCCESS, msg=''):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_int32(authc)
        self.fp.write_string(username)
        self.fp.write_int32(authz)
        self.fp.write_string(msg)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self, parameters):
        # if the username is blank and rootpwmoddn is configured, try to
        # authenticate as administrator, otherwise validate request as usual
        if not parameters['username'] and cfg.rootpwmoddn:
            # authenticate as rootpwmoddn
            binddn = cfg.rootpwmoddn
            # if the caller is root we will allow the use of rootpwmodpw
            if not parameters['password'] and self.calleruid == 0 and cfg.rootpwmodpw:
                password = cfg.rootpwmodpw
            elif parameters['password']:
                password = parameters['password']
            else:
                raise ValueError('password missing')
        else:
            self.validate_request(parameters)
            binddn = parameters['userdn']
            password = parameters['password']
        # try authentication
        try:
            authz, msg = try_bind(userdn, password)
        except ldap.INVALID_CREDENTIALS, e:
            try:
                msg = e[0]['desc']
            except:
                msg = str(e)
            logging.debug('bind failed: %s', msg)
            self.write(parameters['username'], authc=constants.NSLCD_PAM_AUTH_ERR, msg=msg)
            return
        if authz != constants.NSLCD_PAM_SUCCESS:
            logging.warning('%s: %s: %s', userdn, parameters['username'], msg)
        else:
            logging.debug('bind successful')
        # FIXME: perform shadow attribute checks with check_shadow()
        self.write(parameters['username'], authz=authz, msg=msg)


class PAMAuthorisationRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_AUTHZ

    def read_parameters(self, fp):
        return dict(username=fp.read_string(),
                    service=fp.read_string(),
                    ruser=fp.read_string(),
                    rhost=fp.read_string(),
                    tty=fp.read_string())
        # TODO: log call with parameters

    def write(self, authz=constants.NSLCD_PAM_SUCCESS, msg=''):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_int32(authz)
        self.fp.write_string(msg)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def check_authzsearch(self, parameters):
        if not cfg.pam_authz_searches:
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
        for x in cfg.pam_authz_searches:
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
            self.write(constants.NSLCD_PAM_PERM_DENIED,
                       'LDAP authorisation check failed')
            return
        # all tests passed, return OK response
        self.write()


#NSLCD_ACTION_PAM_SESS_O
#NSLCD_ACTION_PAM_SESS_C
#NSLCD_ACTION_PAM_PWMOD
