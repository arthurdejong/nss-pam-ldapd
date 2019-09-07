
# pam.py - functions authentication, authorisation and session handling
#
# Copyright (C) 2010-2019 Arthur de Jong
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
import random
import socket
import time

import ldap
from ldap.controls.ppolicy import PasswordPolicyControl, PasswordPolicyError
from ldap.filter import escape_filter_chars

import cfg
import common
import constants
import passwd
import search
import shadow


random = random.SystemRandom()


def authenticate(binddn, password):
    # open a new connection
    conn = search.Connection()
    # bind using the specified credentials
    pwctrl = PasswordPolicyControl()
    res, data, msgid, ctrls = conn.simple_bind_s(binddn, password, serverctrls=[pwctrl])
    # go over bind result server controls
    for ctrl in ctrls:
        if ctrl.controlType == PasswordPolicyControl.controlType:
            # found a password policy control
            logging.debug(
                'PasswordPolicyControl found: error=%s (%s), '
                'timeBeforeExpiration=%s, graceAuthNsRemaining=%s',
                'None' if ctrl.error is None else PasswordPolicyError(ctrl.error).prettyPrint(),
                ctrl.error, ctrl.timeBeforeExpiration, ctrl.graceAuthNsRemaining)
            if ctrl.error == 0:  # passwordExpired
                return (
                    conn, constants.NSLCD_PAM_AUTHTOK_EXPIRED,
                    PasswordPolicyError(ctrl.error).prettyPrint())
            elif ctrl.error == 1:  # accountLocked
                return (
                    conn, constants.NSLCD_PAM_ACCT_EXPIRED,
                    PasswordPolicyError(ctrl.error).prettyPrint())
            elif ctrl.error == 2:  # changeAfterReset
                return (
                    conn, constants.NSLCD_PAM_NEW_AUTHTOK_REQD,
                    'Password change is needed after reset')
            elif ctrl.error:
                return (
                    conn, constants.NSLCD_PAM_PERM_DENIED,
                    PasswordPolicyError(ctrl.error).prettyPrint())
            elif ctrl.timeBeforeExpiration is not None:
                return (
                    conn, constants.NSLCD_PAM_NEW_AUTHTOK_REQD,
                    'Password will expire in %d seconds' % ctrl.timeBeforeExpiration)
            elif ctrl.graceAuthNsRemaining is not None:
                return (
                    conn, constants.NSLCD_PAM_NEW_AUTHTOK_REQD,
                    'Password expired, %d grace logins left' % ctrl.graceAuthNsRemaining)
    # perform search for own object (just to do any kind of search)
    results = search.LDAPSearch(
        conn, base=binddn, scope=ldap.SCOPE_BASE,
        filter='(objectClass=*)', attributes=['dn'])
    for entry in results:
        if entry[0] == binddn:
            return conn, constants.NSLCD_PAM_SUCCESS, ''
    # if our DN wasn't found raise an error to signal bind failure
    raise ldap.NO_SUCH_OBJECT()


def pwmod(conn, userdn, oldpassword, newpassword):
    # perform request without old password
    try:
        conn.passwd_s(userdn, None, newpassword)
    except ldap.LDAPError:
        # retry with old password
        if oldpassword:
            conn.passwd_s(userdn, oldpassword, newpassword)
        else:
            raise


def update_lastchange(conns, userdn):
    """Try to update the shadowLastChange attribute of the entry."""
    attribute = shadow.attmap['shadowLastChange']
    if str(attribute) == '"${shadowLastChange:--1}"':
        attribute = 'shadowLastChange'
    if not attribute or '$' in str(attribute):
        raise ValueError('shadowLastChange has unsupported mapping')
    # build the value for the new attribute
    if attribute.lower() == 'pwdlastset':
        # for AD we use another timestamp */
        value = '%d000000000' % (int(time.time()) // 100 + (134774 * 864))
    else:
        # time in days since Jan 1, 1970
        value = '%d' % (int(time.time()) // (60 * 60 * 24))
    # perform the modification, return at first success
    for conn in conns:
        try:
            conn.modify_s(userdn, [(ldap.MOD_REPLACE, attribute, [value.encode('utf-8')])])
            return
        except ldap.LDAPError:
            pass  # ignore error and try next connection


class PAMRequest(common.Request):

    def validate(self, parameters):
        """Check the username for validity and fill in the DN if needed."""
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
                logging.warning('%s: is missing a %s attribute', entry[0], passwd.attmap['uid'])
            value = values[0]
        # check the username
        if value and not common.is_valid_name(value):
            raise ValueError('%s: has invalid %s attribute', entry[0], passwd.attmap['uid'])
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
            self.validate(parameters)
            binddn = parameters['userdn']
            password = parameters['password']
        # try authentication
        try:
            conn, authz, msg = authenticate(binddn, password)
        except ldap.INVALID_CREDENTIALS as e:
            try:
                msg = e[0]['desc']
            except Exception:
                msg = str(e)
            logging.debug('bind failed: %s', msg)
            self.write(parameters['username'], authc=constants.NSLCD_PAM_AUTH_ERR, msg=msg)
            return
        if authz != constants.NSLCD_PAM_SUCCESS:
            logging.warning('%s: %s: %s', binddn, parameters['username'], msg)
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

    def check_authz_search(self, parameters):
        if not cfg.pam_authz_searches:
            return
        # escape all parameters
        variables = dict((k, escape_filter_chars(v)) for k, v in parameters.items())
        variables.update(
            hostname=escape_filter_chars(socket.gethostname()),
            fqdn=escape_filter_chars(socket.getfqdn()),
            dn=variables['userdn'],
            uid=variables['username'])
        # go over all authz searches
        for x in cfg.pam_authz_searches:
            filter = x.value(variables)
            logging.debug('trying pam_authz_search "%s"', filter)
            srch = search.LDAPSearch(self.conn, filter=filter, attributes=('dn', ))
            try:
                dn, values = srch.items().next()
            except StopIteration:
                logging.error('pam_authz_search "%s" found no matches', filter)
                raise
            logging.debug('pam_authz_search found "%s"', dn)

    def handle_request(self, parameters):
        # fill in any missing userdn, etc.
        self.validate(parameters)
        # check authorisation search
        try:
            self.check_authz_search(parameters)
        except StopIteration:
            self.write(constants.NSLCD_PAM_PERM_DENIED,
                       'LDAP authorisation check failed')
            return
        # all tests passed, return OK response
        self.write()


class PAMPasswordModificationRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_PWMOD

    def read_parameters(self, fp):
        return dict(username=fp.read_string(),
                    service=fp.read_string(),
                    ruser=fp.read_string(),
                    rhost=fp.read_string(),
                    tty=fp.read_string(),
                    asroot=fp.read_int32(),
                    oldpassword=fp.read_string(),
                    newpassword=fp.read_string())
        # TODO: log call with parameters

    def write(self, rc=constants.NSLCD_PAM_SUCCESS, msg=''):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_int32(rc)
        self.fp.write_string(msg)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self, parameters):
        # fill in any missing userdn, etc.
        self.validate(parameters)
        # check if pam_password_prohibit_message is set
        if cfg.pam_password_prohibit_message:
            self.write(constants.NSLCD_PAM_PERM_DENIED,
                       cfg.pam_password_prohibit_message)
            return
        # check if the the user passed the rootpwmoddn
        if parameters['asroot']:
            binddn = cfg.rootpwmoddn
            # check if rootpwmodpw should be used
            if not parameters['oldpassword'] and self.calleruid == 0 and cfg.rootpwmodpw:
                password = cfg.rootpwmodpw
            elif parameters['oldpassword']:
                password = parameters['oldpassword']
            else:
                raise ValueError('password missing')
        else:
            binddn = parameters['userdn']
            password = parameters['oldpassword']
            # TODO: check if shadow properties allow password change
        # perform password modification
        try:
            conn, authz, msg = authenticate(binddn, password)
            pwmod(conn, parameters['userdn'], parameters['oldpassword'], parameters['newpassword'])
            # try to update lastchange with normal or user connection
            update_lastchange((self.conn, conn), parameters['userdn'])
        except ldap.INVALID_CREDENTIALS as e:
            try:
                msg = e[0]['desc']
            except Exception:
                msg = str(e)
            logging.debug('pwmod failed: %s', msg)
            self.write(constants.NSLCD_PAM_PERM_DENIED, msg)
            return
        logging.debug('pwmod successful')
        self.write()


SESSION_ID_LENGTH = 25
SESSION_ID_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "abcdefghijklmnopqrstuvwxyz" +
    "01234567890"
)


def generate_session_id():
    return ''.join(
        random.choice(SESSION_ID_ALPHABET)
        for i in range(SESSION_ID_LENGTH)
    )


class PAMSessionOpenRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_SESS_O

    def read_parameters(self, fp):
        return dict(username=fp.read_string(),
                    service=fp.read_string(),
                    ruser=fp.read_string(),
                    rhost=fp.read_string(),
                    tty=fp.read_string())
        # TODO: log call with parameters

    def write(self, sessionid):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(sessionid)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self, parameters):
        # generate a session id
        session_id = generate_session_id()
        self.write(session_id)


class PAMSessionCloseRequest(PAMRequest):

    action = constants.NSLCD_ACTION_PAM_SESS_C

    def read_parameters(self, fp):
        return dict(username=fp.read_string(),
                    service=fp.read_string(),
                    ruser=fp.read_string(),
                    rhost=fp.read_string(),
                    tty=fp.read_string(),
                    session_id=fp.read_string())
        # TODO: log call with parameters

    def write(self):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self, parameters):
        self.write()
