#!/usr/local/sbin/charm-env python3
# Copyright 2018 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import os
import sys

# Load modules from $CHARM_DIR/lib
sys.path.append('lib')

from charms.layer import basic
basic.bootstrap_charm_deps()
basic.init_config_states()

import charmhelpers.core.hookenv as hookenv

import charm.vault as vault
import charm.vault_pki as vault_pki
import charms.reactive


def authorize_charm_action(*args):
    """Create a role allowing the charm to perform certain vault actions.
    """
    if not hookenv.is_leader():
        hookenv.action_fail('Please run action on lead unit')
    action_config = hookenv.action_get()
    role_id = vault.setup_charm_vault_access(action_config['token'])
    hookenv.leader_set({vault.CHARM_ACCESS_ROLE_ID: role_id})


def get_intermediate_csrs(*args):
    if not hookenv.is_leader():
        hookenv.action_fail('Please run action on lead unit')
    action_config = hookenv.action_get() or {}
    csrs = vault_pki.get_csr(
        ttl=action_config.get('ttl'),
        country=action_config.get('country'),
        province=action_config.get('province'),
        organization=action_config.get('organization'),
        organizational_unit=action_config.get('organizational-unit'))
    hookenv.action_set({'output': csrs})


def upload_signed_csr(*args):
    if not hookenv.is_leader():
        hookenv.action_fail('Please run action on lead unit')
        return

    action_config = hookenv.action_get()
    root_ca = action_config.get('root-ca')
    if root_ca:
        hookenv.leader_set(
            {'root-ca': base64.b64decode(root_ca).decode("utf-8")})
    vault_pki.upload_signed_csr(
        base64.b64decode(action_config['pem']).decode("utf-8"),
        allowed_domains=action_config.get('allowed-domains'),
        allow_subdomains=action_config.get('allow-subdomains'),
        enforce_hostnames=action_config.get('enforce-hostnames'),
        allow_any_name=action_config.get('allow-any-name'),
        max_ttl=action_config.get('max-ttl'))


def reissue_certificates(*args):
    charms.reactive.set_flag('certificates.reissue.requested')

# Actions to function mapping, to allow for illegal python action names that
# can map to a python function.
ACTIONS = {
    "authorize-charm": authorize_charm_action,
    "get-csr": get_intermediate_csrs,
    "upload-signed-csr": upload_signed_csr,
    "reissue-certificates": reissue_certificates,
}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            hookenv.action_fail(str(e))
        else:
            charms.reactive.main()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
