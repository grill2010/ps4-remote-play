# Copyright (c) 2018, Pierre Bourdon <delroth@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""
The connection module handles the protocol used to connect to the PS4 as
a remote play client. WIP - not working at the moment
"""

import binascii
import requests
import base64
import uuid


from ps4rp import crypto

_RP_CONTROL_PORT = 9295


def connect_to_console(ip, registration_key, rp_key):
    """Connect to console"""

    ua = {
        'Host': ip + ':' + str(_RP_CONTROL_PORT),
        'User-Agent': 'remoteplay Windows',
        'Connection': 'close',
        'Content-Length': '0',
        'RP-Registkey': binascii.hexlify(registration_key),
        'RP-Version': '8.0'
    }
    resp = requests.get(
        'http://%s:%d/sce/rp/session' % (ip, _RP_CONTROL_PORT),
        headers=ua
    )
    if resp.status_code != 200:
        return None

    rp_nonce = resp.headers['RP-Nonce']

    encoded = base64.b64decode(rp_nonce)
    sess = crypto.Session.for_control_auth(rp_key, encoded)

    # The order for the encryption is important so for better understanding
    # I added a new method which takes the counter as a parameter.

    padded_regist_key = list(registration_key + b'\x00' * 8)
    padded_regist_key = bytes(padded_regist_key)
    rp_auth = sess.encrypt_with_ctr(padded_regist_key, 0)
    rp_auth = base64.b64encode(rp_auth)

    # In regard to the official PS4 Remote Play app on Windows the 'rp-did'
    # is the MachineGuid which you can find in the registry under
    # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
    # In fact the real guid value doesn't matter, the only important
    # thing is to prepend the specific did_prefix to the machine guid
    # and add the correct padding. Here we are just generating a random uuid
    random_did = uuid.uuid4().bytes
    did_prefix = bytes([0x00, 0x18, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x80])
    rp_did = did_prefix + random_did + b'0000000'
    rp_did_encrypted = sess.encrypt_with_ctr(rp_did, 1)
    rp_did_encoded = base64.b64encode(rp_did_encrypted)

    # A correct value for the 'rp-ostype' is Win10.0.0.
    # Other values may work as well but have not been tested
    # I think the padding here is not really needed
    rp_ostype = b'Win10.0.0\x00'
    rp_ostype_encrypted = sess.encrypt_with_ctr(rp_ostype, 2)
    rp_ostype_encoded = base64.b64encode(rp_ostype_encrypted)

    ua = {
        'Host': ip + ':' + str(_RP_CONTROL_PORT),
        'User-Agent': 'remoteplay Windows',
        'Connection': 'keep-alive',
        'Content-Length': '0',
        'RP-Auth': rp_auth,
        'RP-Version': '8.0',
        'RP-Did': rp_did_encoded,
        'RP-ControllerType': '3',
        'RP-ClientType': '11',
        'RP-OSType': rp_ostype_encoded,
        'RP-ConPath': '1'
    }
    
    resp = requests.get(
        'http://%s:%d/sce/rp/session/ctrl' % (ip, _RP_CONTROL_PORT),
        headers=ua
    )
    if resp.status_code != 200:
        return None
    else:
        test = "connected" # You should be connected now as remote play client but you will get disconnected after some time. ToDo figure out how the rest of the protocol is working
