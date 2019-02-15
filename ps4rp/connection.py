# Copyright (c) 2018, Pierre Bourdon <delroth@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""
The connection module handles the protocol used to connect to the PS4 as
a remote play client. WIP - not working at the moment
"""

import binascii
import requests
import base64


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
    
    padded_regist_key = list(registration_key + b'\x00' * 8)
    padded_regist_key = bytes(padded_regist_key)
    rp_auth = sess.encrypt(padded_regist_key)
    rp_auth = base64.b64encode(rp_auth)

    # toDo check how rp-id and rp-ostype are generated
    rp_did = base64.b64encode(binascii.a2b_hex('294d5fa8313229eea86dfbdc7625ed784afea62dc39de6f85be6000000000000'))  # ?
    """
    In the Windows Remote Play app it seems that a valid value is Win10.0.0
    The value is stored in char[16] and the padding to fill the array looks like \0 \0 \0 \t \0 \0 \0
    After that the first 10 chars will get XORed with some unknown values.
    I believe the values will then be encrypted and then encoded with base64.
    """
    rp_osType = base64.b64encode(binascii.a2b_hex('8fb664fea71d06132821'))  # ?

    ua = {
        'Host': ip + ':' + str(_RP_CONTROL_PORT),
        'User-Agent': 'remoteplay Windows',
        'Connection': 'keep-alive',
        'Content-Length': '0',
        'RP-Auth': rp_auth,
        'RP-Version': '8.0',
        'RP-Did': rp_did,
        'RP-ControllerType': '3',
        'RP-ClientType': '11',
        'RP-OSType': rp_osType,
        'RP-ConPath': '1'
    }
    
    resp = requests.get(
        'http://%s:%d/sce/rp/session/ctrl' % (ip, _RP_CONTROL_PORT),
        headers=ua
    )
    if resp.status_code != 200:  # it always returns 403 here because of unknown values for rp-did and rp-ostype
        return None
