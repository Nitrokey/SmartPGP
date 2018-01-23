#!/usr/bin/env python

# SmartPGP : JavaCard implementation of OpenPGP card v3 specification
# https://github.com/ANSSI-FR/SmartPGP
# Copyright (C) 2016 ANSSI

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
from enum import Enum

from smartcard.ATR import ATR
from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.util import toHexString, BinStringToHexList, HexListToBinString

import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format='%(relativeCreated)d  %(funcName)s  %(message)s')
log_commands = logging.getLogger('commands')

import struct

SELECT = [0x00, 0xA4, 0x04, 0x00,
          0x06,
          0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
          0x00]

VERIFY_ADMIN = [0x00, 0x20, 0x00, 0x83]
VERIFY_USER_82 = [0x00, 0x20, 0x00, 0x82]
TERMINATE = [0x00, 0xe6, 0x00, 0x00]
ACTIVATE = [0x00, 0x44, 0x00, 0x00]
ACTIVATE_FULL = [0x00, 0x44, 0x00, 0x01]
GET_SM_CURVE_OID = [0x00, 0xca, 0x00, 0xd4]
GENERATE_ASYMETRIC_KEYPAIR = [0x00, 0x47, 0x80, 0x00]

ALGS_ALIASES = {
    'ansix9p256r1': 'ansix9p256r1',
    'P256': 'ansix9p256r1',
    'P-256': 'ansix9p256r1',
    'NIST-P256': 'ansix9p256r1',
    'ansix9p384r1': 'ansix9p384r1',
    'P384': 'ansix9p384r1',
    'P-384': 'ansix9p384r1',
    'NIST-P384': 'ansix9p384r1',
    'ansix9p521r1': 'ansix9p521r1',
    'P521': 'ansix9p521r1',
    'P-521': 'ansix9p521r1',
    'NIST-P521': 'ansix9p521r1',

    'brainpoolP256r1': 'brainpoolP256r1',
    'BP256': 'brainpoolP256r1',
    'BP-256': 'brainpoolP256r1',
    'brainpool256': 'brainpoolP256r1',
    'brainpoolP384r1': 'brainpoolP384r1',
    'BP384': 'brainpoolP384r1',
    'BP-384': 'brainpoolP384r1',
    'brainpool384': 'brainpoolP384r1',
    'brainpoolP512r1': 'brainpoolP512r1',
    'BP512': 'brainpoolP512r1',
    'BP-512': 'brainpoolP512r1',
    'brainpool512': 'brainpoolP512r1',
}

OID_ALGS = {
    'ansix9p256r1': [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    'ansix9p384r1': [0x2B, 0x81, 0x04, 0x00, 0x22],
    'ansix9p521r1': [0x2B, 0x81, 0x04, 0x00, 0x23],
    'brainpoolP256r1': [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    'brainpoolP384r1': [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
    'brainpoolP512r1': [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
}

class WrongKeyRole(Exception):
    pass

class WrongAlgo(Exception):
    pass

def ascii_encode_pin(pin):
    return [ord(c) for c in pin]

def assemble_with_len(prefix,data):
    """
    https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.3.1.pdf
    7.2  Commands in Detail, page 43
    If the card provides extended Lc/Le than the terminal should extend
    the fields to a length of 2 or 3 bytes for data length >255 (dec.).
    :param prefix:
    :param data:
    :return:
    """
    l = len(data)
    if l>2050:
        raise ValueError('Data size too big')
    if l < 255:
        return prefix + [l] + data # 1 byte unsigned
    elif 255 < l < 256*256:
        b = '\0' + struct.pack('<H', l)  # 3 bytes unsigned
        # b = struct.pack('<H', l)  # 2 bytes unsigned
    else:
        b = struct.pack('<I', l)
    b = BinStringToHexList(b)

    log_commands.debug('Setting data length {} to {}'.format(l, b))

    return prefix + b + data

def asOctets(bs):
    l = len(bs)
    if l%8 is not 0:
        raise "BitString length is not a multiple of 8"
    result = []
    i = 0
    while i < l:
        byte = 0
        for x in range(8):
            byte |= bs[i + x] << (7 - x)
        result.append(byte)
        i += 8
    return result

def encode_len(data):
    l = len(data)
    if l > 0xff:
        l = [0x82, (l >> 8) & 0xff, l & 0xff]
    elif l > 0x7f:
        l = [0x81, l & 0xff]
    else:
        l = [l & 0xff]
    return l

def _raw_send_apdu(connection, text, apdu):
    log_commands.debug(text)
    # log_commands.debug("Sending APDU: " + ' '.join('{:02X}'.format(c) for c in apdu))
    log_commands.debug("Sending APDU: " + toHexString(apdu))
    (data, sw1, sw2) = connection.transmit(apdu)
    data_hexstr = ' '.join('{:02X}'.format(c) for c in data)
    data_hexstr = data_hexstr if data_hexstr else '(empty)'
    log_commands.debug('Returned data: ' + data_hexstr)
    codes = {
        (0x69,0x82) : 'Security status not satisfied. PW wrong. PW not checked (command not allowed). Secure messaging incorrect (checksum and/or cryptogram)',
        (0x90,0x00) : 'Success',
        (0x6B,0x00) : 'Wrong parameters P1-P2',
        (0x67,0x00) : 'Wrong length (Lc and/or Le)',
        (0x6A,0x88) : 'Referenced data not found',
        (0x68,0x82) : 'Secure messaging not supported',
        (0x68,0x84) : 'Command chaining not supported',
    }

    log_commands.debug("Returned: %02X %02X (data len %d) %s" % (sw1, sw2, len(data), codes.get((sw1, sw2), 'Unknown return code')))
    from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
    errorchecker = ISO7816_4ErrorChecker()
    errorchecker([], sw1, sw2)

    return (data,sw1,sw2)

def list_readers():
    for reader in readers():
        try:
            connection = reader.createConnection()
            connection.connect()
            atr_bytes = connection.getATR()
            print(reader, toHexString(atr_bytes))
            atr = ATR(atr_bytes)
            print(atr.dump())
        except NoCardException:
            print(reader, 'no card inserted')

def select_reader(reader_index):
    log_commands.debug('Listing reader')
    reader_list = readers()
    if not reader_list:
        raise NoCardException
    r = reader_list[reader_index]
    log_commands.debug('Selecting reader %d' % reader_index)
    conn = r.createConnection()
    conn.connect()
    log_commands.debug('Connected to %d' % reader_index)
    return conn

def select_applet(connection):
    return _raw_send_apdu(connection,"Select OpenPGP Applet",SELECT)

def verif_admin_pin(connection, admin_pin):
    verif_apdu = assemble_with_len(VERIFY_ADMIN,ascii_encode_pin(admin_pin))
    return _raw_send_apdu(connection,"Verify Admin PIN",verif_apdu)

def verif_user_pin(connection, user_pin):
    verif_apdu = assemble_with_len(VERIFY_USER_82,ascii_encode_pin(user_pin))
    return _raw_send_apdu(connection,"Verify User PIN",verif_apdu)

def full_reset_card(connection):
    _raw_send_apdu(connection,"Terminate",TERMINATE)
    _raw_send_apdu(connection,"Activate",ACTIVATE_FULL)

def reset_card(connection):
    _raw_send_apdu(connection,"Terminate",TERMINATE)
    _raw_send_apdu(connection,"Activate",ACTIVATE)

def switch_crypto_rsa(connection,key_role):
    data = [
        0x01,       # RSA
        0x08, 0x00, # 2048 bits modulus
        0x00, 0x11, # 65537 - 17 bits public exponent
        0x03]       # crt form with modulus
    if key_role == 'sig':
        role = 0xc1
    elif key_role == 'dec':
        role = 0xc2
    elif key_role == 'auth':
        role = 0xc3
    elif key_role == 'sm':
        role = 0xd4
    else:
        raise WrongKeyRole
    prefix = [0x00, 0xDA, 0x00] + [role]
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Switch to RSA2048 (%s)" % (key_role,),apdu)

def switch_crypto(connection,crypto,key_role):
    alg_name = None
    role = None
    # treat RSA differently
    if crypto=='rsa2048' or crypto=='RSA2048' or crypto=='rsa' or crypto=='RSA':
        return switch_crypto_rsa(connection,key_role)
    # this code is only for elliptic curves
    try:
        alg_name = ALGS_ALIASES[crypto]
    except KeyError:
        raise WrongAlgo
    data = OID_ALGS[alg_name]
    byte1 = 0x12
    if key_role == 'sig':
        role = 0xc1
        byte1 = 0x13
    elif key_role == 'dec':
        role = 0xc2
    elif key_role == 'auth':
        role = 0xc3
    elif key_role == 'sm':
        role = 0xd4
    else:
        raise WrongKeyRole
    prefix = [0x00, 0xDA, 0x00] + [role]
    apdu = assemble_with_len(prefix, [byte1] + data + [0xff])
    _raw_send_apdu(connection,"Switch to %s (%s)" % (crypto,key_role),apdu)

def generate_sm_key(connection):
    apdu = assemble_with_len(GENERATE_ASYMETRIC_KEYPAIR, [0xA6, 0x00])
    apdu = apdu + [0x00]
    return _raw_send_apdu(connection,"Generate SM key",apdu)

def set_resetting_code(connection, resetting_code):
    apdu = assemble_with_len([0x00, 0xDA, 0x00, 0xD3], ascii_encode_pin(resetting_code))
    _raw_send_apdu(connection,"Define the resetting code (PUK)",apdu)

def unblock_pin(connection, resetting_code, new_user_pin):
    data = ascii_encode_pin(resetting_code)+ascii_encode_pin(new_user_pin)
    apdu = assemble_with_len([0x00, 0x2C, 0x00, 0x81], data)
    _raw_send_apdu(connection,"Unblock user PIN with resetting code",apdu)

def put_sm_key(connection, pubkey, privkey):
    ins_p1_p2 = [0xDB, 0x3F, 0xFF]
    cdata = [0x92] + encode_len(privkey) + [0x99] + encode_len(pubkey)
    cdata = [0xA6, 0x00, 0x7F, 0x48] + encode_len(cdata) + cdata
    cdata = cdata + [0x5F, 0x48] + encode_len(privkey + pubkey) + privkey + pubkey
    cdata = [0x4D] + encode_len(cdata) + cdata
    i = 0
    cl = 255
    l = len(cdata)
    while i < l:
        if (l - i) <= cl:
            cla = 0x00
            data = cdata[i:]
            i = l
        else:
            cla = 0x10
            data = cdata[i:i+cl]
            i = i + cl
        apdu = assemble_with_len([cla] + ins_p1_p2, data)
        _raw_send_apdu(connection,"Sending SM key chunk",apdu)

def put_sm_certificate(connection, cert):
    prefix = [0x00, 0xA5, 0x03, 0x04]
    data = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Selecting SM certificate",apdu)
    ins_p1_p2 = [0xDA, 0x7F, 0x21]
    i = 0
    cl = 255
    l = len(cert)
    while i < l:
        if (l - i) <= cl:
            cla = 0x00
            data = cert[i:]
            i = l
        else:
            cla = 0x10
            data = cert[i:i+cl]
            i = i + cl
        apdu = assemble_with_len([cla] + ins_p1_p2, data)
        _raw_send_apdu(connection,"Sending SM certificate chunk",apdu)

def get_sm_certificate(connection):
    prefix = [0x00, 0xA5, 0x03, 0x04]
    data = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21]
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Selecting SM certificate",apdu)
    apdu = [0x00, 0xCA, 0x7F, 0x21, 0x00]
    (data,sw1,sw2) = _raw_send_apdu(connection,"Receiving SM certificate chunk",apdu)
    while sw1 == 0x61:
        apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
        (ndata,sw1,sw2) = _raw_send_apdu(connection,"Receiving SM certificate chunk",apdu)
        data = data + ndata
    return (data,sw1,sw2)

def get_sm_curve_oid(connection):
    """ Get Curve OID for Secure Messaging
        Return Curve OID (DER-encoded)
    """
    apdu = GET_SM_CURVE_OID + [0x00]
    (data,sw1,sw2) = _raw_send_apdu(connection,"SM Curve OID",apdu)
    b = bytearray(data)
    assert(b[0]==0xd4)
    curve_len = b[1]
    curve = b[2:]
    assert(curve_len == len(curve))
    assert(curve[0])==0x12
    curve = curve[1:]
    if curve[-1] == 0xff:
        curve.pop()
    print ' '.join('{:02X}'.format(c) for c in curve)
    # Add DER OID header manually ...
    return '\x06' + struct.pack('B',len(curve)) + curve

def put_aes_key(connection, key):
    prefix = [0x00, 0xDA, 0x00, 0xD5]
    data = key
    apdu = assemble_with_len(prefix, data)
    _raw_send_apdu(connection,"Put AES key",apdu)


def get_info(connection, DO=None, length=10):
    if DO is None:
        # DO = [0xC0, 0x00]
        DO = [0x5F, 0x52]
        # DO = [0x7F, 0x74]

    command = [0x0, 0xca] + DO + [length]
    apdu = command
    (data, sw1, sw2) = _raw_send_apdu(connection, "Get info/DO object", apdu)

    return (data[:-2],sw1,sw2)

def round_to_multiply_of_ceil(value, m=16):
    return int(value) - int(value) % int(m) + m

def zero_pad(msg, multiply=32):
    """

    :param msg: str
    :type multiply: int
    """
    l = len(msg)
    l_rounded = round_to_multiply_of_ceil(l, multiply) - l
    msg += [0]*l_rounded
    return msg

def encrypt_aes(connection, msg):
    data_to_return = []
    ins_p1_p2 = [0x2A, 0x86, 0x80]
    i = 0
    cl = 240
    sw1 = 0
    sw2 = 0

    # write original msg length
    l = len(msg)
    lp = struct.pack('!Q', l) # content size in 8 bytes unsigned long long, network (= big-endian)
    assert (len(lp) == 8)
    lp = BinStringToHexList(lp)
    data_to_return = lp

    # pad with '0's to size being multiply of 16
    msg = zero_pad(msg, multiply=32)
    l = len(msg)

    from tqdm import tqdm
    with tqdm(total=l) as pbar:
        while i < l:
            pbar.update(cl)
            if (l - i) <= cl:
                cla = 0x00
                data = msg[i:]
                i = l
            else:
                cla = 0x00
                data = msg[i:i+cl]
                i = i + cl
            log_commands.debug("Lenght of data sent: {}".format(len(data)))
            apdu = assemble_with_len([cla] + ins_p1_p2, data) + [0]
            (res,sw1,sw2) = _raw_send_apdu(connection,"Encrypt AES chunk",apdu)
            res = res[1:]
            log_commands.debug("Lenght of data: {}".format(len(res)))
            data_to_return = data_to_return + res
            while sw1 == 0x61:
                apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
                (nres,sw1,sw2) = _raw_send_apdu(connection,"Receiving encrypted chunk",apdu)
                data_to_return = data_to_return + nres
    return (data_to_return,sw1,sw2)


def decrypt_aes(connection, msg):
    data_to_return = []
    ins_p1_p2 = [0x2A, 0x80, 0x86]
    i = 0
    cl = 240
    original_l = struct.unpack('!Q', HexListToBinString(msg[:8]))[0]
    msg = msg[8:]
    l = len(msg)
    log_commands.debug("Lenght of msg: {}".format(l))

    from tqdm import tqdm
    with tqdm(total=l) as pbar:
        while i < l:
            pbar.update(cl)
            if (l - i) <= cl:
                cla = 0x00
                data = msg[i:]
                i = l
            else:
                cla = 0x00
                data = msg[i:i+cl]
                i = i + cl

            data = [0x02] + data
            log_commands.debug("Length of data: {}".format(len(data)))
            apdu = assemble_with_len([cla] + ins_p1_p2, data) + [0]
            log_commands.debug("apdu {} {}".format(len(apdu), apdu))
            (res,sw1,sw2) = _raw_send_apdu(connection,"Decrypt AES chunk",apdu)
            data_to_return = data_to_return + res
            while sw1 == 0x61:
                apdu = [0x00, 0xC0, 0x00, 0x00, sw2]
                (nres,sw1,sw2) = _raw_send_apdu(connection,"Receiving decrypted chunk",apdu)
                data_to_return = data_to_return + nres
    data_to_return = data_to_return[:original_l] # trim to original size
    return (data_to_return,sw1,sw2)


class MSEType(Enum):
    Authentication = 0xA4
    Confidentiality = 0xB8


class MSEKeyRef(Enum):
    PSO_DEC = 0x02
    INT_AUT = 0x03


def set_mse(connection, mse_type, mse_key):
    """

    :type mse_key: MSEKeyRef
    :type mse_type: MSEType
    """
    # from page 69, 7.2.18 MANAGE SECURITY ENVIRONMENT
    # https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.3.1.pdf
    cla = 0x00
    ins_p1_p2 = [0x22, 0x41, mse_type.value]
    lc = 0x03
    data = [0x83, 0x01, mse_key.value]

    apdu = assemble_with_len([cla] + ins_p1_p2, data)
    assert len(apdu) - 5 == lc
    assert apdu[4] == lc

    _raw_send_apdu(connection, "MSE, type %s, key %s" % ( str(mse_type), str(mse_key)), apdu)

    return None


class PaddingRSAType(Enum):
    INT_AUTH = 0x01
    PSO_DECIPHER = 0x02


def padding_RSA(data, block_type, key_len=2048):
    """
    N not longer than 40% of the key modulus
    :type block_type: PaddingRSAType
    :param key_len: RSA key length in bits
    :param data: data to sign
    :return: RSA padded data
    """
    from math import floor
    if block_type == PaddingRSAType.INT_AUTH:
        Lc = (key_len / 8) * 0.4
    elif block_type == PaddingRSAType.PSO_DECIPHER:
        Lc = (key_len / 8)
    else:
        raise ValueError()

    # target data field length (also called 'N')
    Lc = int(floor(Lc))
    # user data field length
    L = len(data)
    assert L <= Lc

    padding_length = (Lc - 3 - L)
    if block_type == PaddingRSAType.PSO_DECIPHER:
        # specification requirement
        assert padding_length >= 8

    FFs = padding_length * '\xFF'
    FFs = map(ord, FFs)
    r = [0x00, block_type.value] + FFs + [0x00] + data
    return r


def internal_authenticate(connection, data):
    """
    Needs User PIN (82) to be used.
    ECDSA - cryptogram only
    RSA - needs to be padded
    :param connection:
    :param data: data to sign
    :return: signed data
    """
    cla = 0x00
    ins_p1_p2 = [0x88, 0x00, 0x00]
    data = padding_RSA(data, PaddingRSAType.INT_AUTH)

    apdu = assemble_with_len([cla] + ins_p1_p2, data) + [0]
    (data, sw1, sw2) = _raw_send_apdu(connection, "Internal authentication", apdu)

    return data


def pso_decipher(connection, data):
    """
    Needs User PIN (82) to be used.

    :param connection:
    :param data:
    :return:
    """
    cla = 0x00
    ins_p1_p2 = [0x2A, 0x80, 0x86]
    RSA_padding_indicator = [0x00]
    data = RSA_padding_indicator + padding_RSA(data, PaddingRSAType.PSO_DECIPHER)

    apdu = assemble_with_len([cla] + ins_p1_p2, data) + [1,0]
    (data, sw1, sw2) = _raw_send_apdu(connection, "PSO Decipher", apdu)

    return data
