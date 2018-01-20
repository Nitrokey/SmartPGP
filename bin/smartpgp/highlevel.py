
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

import binascii
from pprint import pprint

import yaml

import commands
from os import urandom

from commands import *
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1.type import univ
from smartcard.util import BinStringToHexList, HexListToBinString


class ConnectionFailed(Exception):
    pass

class AdminPINFailed(Exception):
    pass

class UserPINFailed(Exception):
    pass

class CardConnectionContext:

    def __init__(self):
        self.reader_index = 0
        self.user_pin = "123456"
        self.admin_pin = "12345678"
        self.connection = None
        self.read_pin = self._default_pin_read_function
        self.connected = False
        self.verified = False
        self.input = None
        self.arg1 = None
        self.arg2 = None

    def _default_pin_read_function(self, pin_type):
        pin = {'User': self.user_pin,
         'Admin': self.admin_pin}
        return pin[pin_type]

    def set_pin_read_function(self, fun):
        self.read_pin = fun

    def verify_admin_pin(self):
        # if self.verified:
        #     return
        admin_pin = self.read_pin("Admin")
        (_,sw1,sw2)=verif_admin_pin(self.connection, admin_pin)
        if sw1==0x90 and sw2==0x00:
            self.verified = True
        else:
            raise AdminPINFailed

    def verify_user_pin(self):
        # if self.verified:
        #     return
        user_pin = self.read_pin("User")
        (_,sw1,sw2)=verif_user_pin(self.connection, user_pin)
        if sw1==0x90 and sw2==0x00:
            self.verified = True
        else:
            raise UserPINFailed

    def connect(self):
        if self.connected:
            return
        self.connection = select_reader(self.reader_index)
        (_,sw1,sw2)=select_applet(self.connection)
        if sw1==0x90 and sw2==0x00:
            self.connected = True
        else:
            raise ConnectionFailed

    def cmd_list_readers(self):
        list_readers()

    def cmd_full_reset(self):
        # ignore errors
        self.connection = select_reader(self.reader_index)
        select_applet(self.connection)
        # do not use self.verify_admin_pin(), we want to force sending the APDUs
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        full_reset_card(self.connection)
        # force re-entering admin PIN
        self.verified = False

    def cmd_reset(self):
        # ignore errors
        self.connection = select_reader(self.reader_index)
        select_applet(self.connection)
        # do not use self.verify_admin_pin(), we want to force sending the APDUs
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        verif_admin_pin(self.connection, self.admin_pin)
        reset_card(self.connection)
        # force re-entering admin PIN
        self.verified = False

    def cmd_switch_crypto(self,alg_name,key_role):
        self.connect()
        self.verify_admin_pin()
        switch_crypto(self.connection,alg_name,key_role)

    def cmd_switch_all_crypto(self,alg_name):
        self.connect()
        self.verify_admin_pin()
        switch_crypto(self.connection,alg_name,'sig')
        switch_crypto(self.connection,alg_name,'dec')
        switch_crypto(self.connection,alg_name,'auth')

    def cmd_switch_bp256(self):
        self.cmd_switch_all_crypto('brainpoolP256r1')

    def cmd_switch_bp384(self):
        self.cmd_switch_all_crypto('brainpoolP384r1')

    def cmd_switch_bp512(self):
        self.cmd_switch_all_crypto('brainpoolP512r1')

    def cmd_switch_p256(self):
        self.cmd_switch_all_crypto('P-256')

    def cmd_switch_p384(self):
        self.cmd_switch_all_crypto('P-384')

    def cmd_switch_p521(self):
        self.cmd_switch_all_crypto('P-521')

    def cmd_switch_rsa2048(self):
        self.cmd_switch_all_crypto('rsa2048')

    def cmd_generate_sm_key(self):
        if not self.output:
            print "Missing output file name"
            return
        self.connect()
        self.verify_admin_pin()
        (data,sw1,sw2) = generate_sm_key(self.connection)
        if sw1!=0x90 or sw2!=0x00:
            print "generate_sm_key failed"
            return
        if len(data) < 4 or data[0]!=0x7f or data[1]!=0x49:
            print "Strange reply for get_sm_certificate"
            return
        blob_len = data[2]
        blob = data[3:]
        assert(blob_len == len(blob))
        if blob[0]!=0x86:
            print "get_sm_certificate return something not a public key"
            return
        assert(blob[1]==len(blob[2:]))
        pubkey = blob[2:]
        # get curve OID
        curve_oid_der = get_sm_curve_oid(self.connection)
        if not curve_oid_der:
            print "Error getting SM curve OID"
            return
        (curve_oid,_) = der_decoder.decode(str(curve_oid_der))
        # now format it to DER [RFC5480]
        s = univ.Sequence()
        oid_elliptic_curve_pubkey = univ.ObjectIdentifier('1.2.840.10045.2.1')
        s.setComponentByPosition(0,oid_elliptic_curve_pubkey)
        s.setComponentByPosition(1,curve_oid)
        bs = univ.BitString("'%s'H" % binascii.hexlify(bytearray(pubkey)))
        s2 = univ.Sequence()
        s2.setComponentByPosition(0,s)
        s2.setComponentByPosition(1,bs)
        pubkey_der = der_encoder.encode(s2)
        print binascii.hexlify(pubkey_der)
        # and write result
        with open(self.output,"wb") as f:
            f.write(pubkey_der)
            f.close()

    def cmd_put_sm_key(self):
        if self.input is None:
            print "No input key file"
            return
        f = open(self.input, 'rb')
        fstr = f.read()
        f.close()
        (der,_) = der_decoder.decode(fstr)
        privkey = [ord(c) for c in der[1].asOctets()]
        oid = bytearray(der_encoder.encode(der[2]))
        pubkey = asOctets(der[3])
        if oid[0] == 0xa0:
            oid = oid[2:]
        oid_len = oid[1]
        oid = oid[2:]
        assert(oid_len == len(oid))
        curve = None
        for k,v in OID_ALGS.items():
            if bytearray(v) == oid:
                curve = k
        if curve is None:
            print "Curve not supported (%s)" % der[2]
            return
        self.connect()
        self.verify_admin_pin()
        switch_crypto(self.connection, curve, 'sm')
        put_sm_key(self.connection, pubkey, privkey)

    def cmd_set_resetting_code(self):
        self.connect()
        self.verify_admin_pin()
        resetting_code = self.read_pin("PUK")
        set_resetting_code(self.connection, resetting_code)

    def cmd_unblock_pin(self):
        self.connect()
        resetting_code = self.read_pin("PUK")
        new_user_pin = self.read_pin("new user")
        unblock_pin(self.connection, resetting_code, new_user_pin)

    def cmd_put_sm_certificate(self):
        if self.input is None:
            print "No input certificate file"
            return
        f = open(self.input, 'rb')
        cert = f.read()
        cert = [ord(c) for c in cert]
        f.close()
        self.connect()
        self.verify_admin_pin()
        put_sm_certificate(self.connection, cert)

    def cmd_get_sm_certificate(self):
        if self.output is None:
            print "No output file"
            return
        self.connect()
        (cert,_,_) = get_sm_certificate(self.connection)
        cert = "".join([chr(c) for c in cert])
        with open(self.output, 'wb') as f:
            f.write(cert)
            f.close()

    def cmd_put_aes_key(self):
        if self.input is None:
            print "No input AES key file"
            print "Generating AES key on-the-fly"
            key = urandom(16)
            key = [ord(c) for c in key]
            print "Setting key to %d bytes" % len(key), key
        else:
            with open(self.input, 'rb') as f:
                key = f.read()
                key = [ord(c) for c in key]
        self.connect()
        self.verify_admin_pin()
        put_aes_key(self.connection, key)

    def cmd_encrypt_aes(self):
        if self.input is None:
            print "No input data file"
            return
        if self.output is None:
            self.output = self.input + '.enc'
        if self.input is not '-':
            with open(self.input, 'rb') as f:
                data = f.read()
        else:
            import sys
            data = sys.stdin.read()
            self.output = 'output.enc'

        self.connect()
        self.verify_user_pin()

        data = [ord(c) for c in data]
        (data,_,_) = encrypt_aes(self.connection, data)
        data = HexListToBinString(data)

        if not data:
            print('Device returned no data. Make sure you have written AES key to it.')
        with open(self.output, 'wb') as f:
            print('Writing {} bytes'.format(len(data)))
            f.write(data)

    def cmd_set_mse(self):
        self.connect()

        if self.arg1 is None or self.arg2 is None:
            print('Wrong arguments provided')
            return
        raise NotImplementedError()

    def cmd_mse_test(self):
        self.connect()
        self.verify_user_pin()

        data, _, _ = commands.get_info(self.connection, [0x0, 0x6E], 0)
        data = self.helper_dissect(data)

        extended_capabilities_string = data['73']['C0']
        from functools import partial
        data_in_bytes = map(partial(int, base=16), extended_capabilities_string.split())
        MSE_supported = data_in_bytes[0xa - 1] == 1

        print(extended_capabilities_string)
        print('MSE supported (10th byte set to 0x01): ' + str(MSE_supported))
        assert MSE_supported

        data1 = commands.pso_decipher(self.connection, range(1,33))



        data1 = commands.internal_authenticate(self.connection, [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        commands.set_mse(self.connection, MSEType.Authentication, MSEKeyRef.PSO_DEC)
        data2 = commands.internal_authenticate(self.connection, [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        commands.set_mse(self.connection, MSEType.Authentication, MSEKeyRef.INT_AUT)
        data3 = commands.internal_authenticate(self.connection, [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])

        # Test element-wise
        assert data1 == data3
        assert data1 != data2
        print('Test for internal authentication with different keys passed.')

        # commands.set_mse(self.connection, MSEType.Confidentiality, MSEKeyRef.INT_AUT)
        # commands.set_mse(self.connection, MSEType.Confidentiality, MSEKeyRef.PSO_DEC)


    def helper_dissect(self, constr):
        # dissect constructed data
        d = {}
        i = 0
        j = 0
        data = constr
        while i < len(constr):
            tag = [data[i]]
            if tag[0] == 0:
                d['unrecognized'] = toHexString(data[i:])
                break
            if tag[0] in [0x01, 0x5f, 0x7f]:
                # tag = data[i:i+1]
                tag = [data[i], data[i+1]]

            p = i + len(tag)
            l = data[p]
            p += 1
            tag_data = data[p:p+l]

            # TODO add other constructed tags here as list
            if tag[0] == 0x73:
                # FIXME interpret skipped two bytes
                tag_data = self.helper_dissect(data[i+3:])
            else:
                if tag[0] == 0xC0:
                    first_bin = "First byte in bin: {}".format(format(tag_data[0], '08b'))
                    d[toHexString(tag)+'-info'] = first_bin
                tag_data = toHexString(tag_data)

            tag = toHexString(tag) # + ' (%s)' % hex(l)
            d[tag] = tag_data
            # data = data[1+len+1]
            j += 1
            if j > 100:
                print i, tag, d
                raise RuntimeError('Forever loop')
            i = p + l
        return d

    def cmd_show_info(self):
        self.connect()
        self.verify_admin_pin()

        DO = {
            'Application Related Data': ([0x0, 0x6E], 0),
            'General feature management (optional)': ([0x7F, 0x74], 3),
            'Extended length information (ISO 7816-4) with maximum '
            'number of bytes for command and response': ([0x7F, 0x76], 8),
            'Historical bytes, Card service data and Card capabilities '
            ', mandatory': ([0x5F, 0x52], 10),

        }
        for name, (do, len) in DO.items():
            val = None
            try:
                val = get_info(self.connection, do, len)
            except:
                pass
            print '--', name
            if val:
                if len == 0:
                    print yaml.dump(self.helper_dissect(val[0]), default_flow_style=False)
                else:
                    print map(toHexString, [val[0]])

            else:
                print 'None'


    def cmd_aes_test(self):
        from smartcard.util import HexListToBinString, BinStringToHexList
        plaintext = 'AES encryption test'.center(32,'=') * 200

        key_ = urandom(32)
        key = [ord(c) for c in key_]

        self.connect()
        self.verify_admin_pin()
        put_aes_key(self.connection, key)

        from Crypto.Cipher import AES
        cipher = AES.new(key_)
        data = cipher.encrypt(plaintext)
        import struct
        lp = struct.pack('!Q', len(plaintext))
        data = lp + data
        data = [ord(c) for c in data]

        # plaintext = [ ord(c) for c in plaintext ]
        # (data,_,_) = encrypt_aes(self.connection, plaintext)

        self.verify_user_pin()
        (data,_,_) = decrypt_aes(self.connection, data)
        data = HexListToBinString(data)
        print ('{} / {}'.format(data[:32], plaintext[:32]))
        print ('{} / {}'.format(len(data), len(plaintext)))

        if len(data) == len(plaintext):
            for i in range(len(data)):
                if not data[i] == plaintext[i]:
                    print ((i, data[i], plaintext[i]))
                    print (data[i-5:i+5], plaintext[i-5:i+5])
                    break

        assert data == plaintext

    def cmd_aes_test2(self):
        from smartcard.util import HexListToBinString, BinStringToHexList

        block_size = 16
        plaintext_o = 'testabcdefgh'*1024

        key_ = urandom(block_size)
        key = [ord(c) for c in key_]

        self.connect()
        self.verify_admin_pin()
        put_aes_key(self.connection, key)

        plaintext = [ ord(c) for c in plaintext_o ]
        self.verify_user_pin()
        (data,_,_) = encrypt_aes(self.connection, plaintext)


        self.verify_user_pin()
        (data, _, _) = decrypt_aes(self.connection, data)
        data = HexListToBinString(data)
        print repr((data[:10], plaintext_o[:10]))
        assert data == plaintext_o

    def cmd_decrypt_aes(self):
        if self.input is None:
            print "No input data file"
            return
        if self.output is None:
            self.output = self.input + '.dec'
        with open(self.input, 'rb') as f:
            data = f.read()
        data = [ord(c) for c in data]
        self.connect()
        self.verify_user_pin()
        (data,_,_) = decrypt_aes(self.connection, data)
        data = "".join([chr(c) for c in data])
        if not data:
            print('Device returned no data. Make sure you have written AES key to it.')
        with open(self.output, 'wb') as f:
            f.write(data)

