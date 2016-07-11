# Copyright (C) 2014 Universidad Politecnica de Madrid
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

import urllib

from keystoneclient import base


LOG = logging.getLogger(__name__)

EXTENSION_PATH = '/OS-TWO-FACTOR'

class Key(base.Resource):
    pass


class KeyManager(base.Manager):
    """Manager class for creating/deleting two factor keys."""

    resource_class = Key
    auth_url = '/two_factor_auth'
    security_question_url = '/sec_question'
    two_factor_data_url = '/two_factor_data'
    devices_url = '/devices'

    def _url(self, user):
        return '/users/{user_id}'.format(user_id=base.getid(user)) + EXTENSION_PATH

    def _auth_url(self, user):
        return self._url(user) + self.auth_url

    def _security_question_url(self, user):
        return self._url(user) + self.security_question_url

    def _two_factor_data_url(self, user):
        return self._url(user) + self.two_factor_data_url

    def _devices_url(self, user):
        return self._url(user) + self.devices_url

    def _check_base_url(self):
        return EXTENSION_PATH + self.auth_url

    def generate_new_key(self, user, security_question, security_answer):
        if security_question and security_answer:
            data = {}
            data["two_factor_auth"] = {}
            data["two_factor_auth"]["security_question"] = security_question
            data["two_factor_auth"]["security_answer"] = security_answer
        else:
            data = None

        return super(KeyManager, self)._post(body=data, 
                                             url=self._auth_url(user),
                                             response_key="two_factor_auth")
    
    def deactivate_two_factor(self, user):
        return super(KeyManager, self)._delete(url=self._auth_url(user))

    def check_activated_two_factor(self, **kwargs):
        try:
            super(KeyManager, self)._head(url=self._check_base_url() + '?' + urllib.urlencode(kwargs))
            return True
        except:
            return False

    def get_two_factor_data(self, user):
        return super(KeyManager, self)._get(url=self._two_factor_data_url(user),
                                            response_key="two_factor_auth")

    def check_security_question(self, user, security_answer):

        return super(KeyManager, self)._head(url=self._security_question_url(user) + '?sec_answer=' + security_answer)

    def remember_device(self, **kwargs):
        return super(KeyManager, self)._post(body={},
                                             url=EXTENSION_PATH+'/devices?'+urllib.urlencode(kwargs),
                                             response_key="two_factor_auth")

    def delete_all_devices(self, user):
        return super(KeyManager, self)._delete(url=self._devices_url(user))

    def check_for_device(self, **kwargs):
        return super(KeyManager, self)._head(url=EXTENSION_PATH+'/devices?'+urllib.urlencode(kwargs))
