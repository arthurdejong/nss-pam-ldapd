
# config.py - routines for getting configuration information
#
# Copyright (C) 2013 Arthur de Jong
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

import cfg
import common
import constants


class ConfigGetRequest(common.Request):

    action = constants.NSLCD_ACTION_CONFIG_GET

    def read_parameters(self, fp):
        return dict(cfgopt=fp.read_int32())
        # TODO: log call with parameters

    def write(self, value):
        self.fp.write_int32(constants.NSLCD_RESULT_BEGIN)
        self.fp.write_string(value)
        self.fp.write_int32(constants.NSLCD_RESULT_END)

    def handle_request(self, parameters):
        cfgopt = parameters['cfgopt']
        if cfgopt == constants.NSLCD_CONFIG_PAM_PASSWORD_PROHIBIT_MESSAGE:
            self.write(cfg.pam_password_prohibit_message or '')
        else:
            # return empty response
            self.fp.write_int32(constants.NSLCD_RESULT_END)
