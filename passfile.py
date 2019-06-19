#!/usr/bin/env python3
# coding: utf-8
# vi: tabstop=8 expandtab shiftwidth=4 softtabstop=4

# INSTALL via pip3:
# apt install coreutils python3 python3-pip libxdo3 libx11-6
# pip3 install pycryptodome PyYAML python-libxdo keyring

# INSTALL via packages only:
# apt install coreutils python3 python3-pip libxdo3 python3-pycryptodome python3-yaml python3-keyring
# pip3 install -U python-libxdo

import sys
import os
import functools
import chardet
import inspect
import tempfile
import struct
import getpass
import argparse
import time
import keyring
import string
import base64
import shutil

from Cryptodome.Cipher import ChaCha20 as CryptoAlgo
from Cryptodome.Protocol import KDF as CryptoKdf
from Cryptodome.Hash import BLAKE2b as CryptoSum
import yaml

try:
    from dbus.mainloop.glib import DBusGMainLoop
    DBusGMainLoop(set_as_default=True)
except Exception:
    pass

have_xdo = True
try:
    import xdo
except ImportError:
    have_xdo = False


class EncryptionKeyNotFound(Exception):
    pass


class PassfileNotFound(Exception):
    pass


class BadPassfile(Exception):
    pass


def ensure_utf8(utf8_args):
    if isinstance(utf8_args, str):
        utf8_args = [utf8_args]

    def ensure_utf8_func(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            new_kwargs = {}
            func_args = inspect.getcallargs(f, *args, **kwargs)
            for k, v in func_args.items():
                if k in utf8_args:
                    if isinstance(v, str):
                        new_kwargs[k] = v.encode('utf-8')
                    elif isinstance(v, bytes):
                        detected_encoding = chardet.detect(v)['encoding']
                        if detected_encoding is not None and detected_encoding != 'utf-8':
                            new_kwargs[k] = v.decode(detected_encoding).encode('utf-8')
                        else:
                            new_kwargs[k] = v
                    else:
                        raise TypeError("Please, specify only text type arguments for ensure_utf8")
                else:
                    new_kwargs[k] = v
            return f(**new_kwargs)
        return wrapper
    return ensure_utf8_func


class SecurePassfileCrypto():
    def __init__(self, ns):
        self.ns = 'pass_' + ns
        self.salt = None
        self.iv = None
        self.metadata_format = 'i8s'
        self.metadata_size = struct.calcsize(self.metadata_format)
        self.metadata_version = 1

    def _renew_iv(self):
        self.iv = os.urandom(8)

    def reset_key(self):
        user_key = getpass.getpass("Key: ")
        salt = os.urandom(8)
        key = CryptoKdf.scrypt(user_key, salt, 32, 262144, 8, 1)
        key = base64.b85encode(key)  # https://github.com/jaraco/keyring/issues/388
        del user_key
        keyring.set_password(self.ns, getpass.getuser(), key)

    def get_metadata(self):
        return struct.pack(self.metadata_format, self.metadata_version, self.iv)

    def set_metadata(self, metadata):
        self.metadata_version, self.iv = struct.unpack(self.metadata_format, metadata[0:self.metadata_size])

    def _crypt(self, mode, data):
        assert mode in ['enc', 'dec'], 'Mode must be "enc" or "dec"'
        if mode == 'enc':
            self._renew_iv()

        key = keyring.get_password(self.ns, getpass.getuser())
        if key is None:
            raise EncryptionKeyNotFound
        else:
            key = base64.b85decode(key)

        cipher = CryptoAlgo.new(key=key, nonce=self.iv)

        if mode == 'enc':
            res = cipher.encrypt(data)
        else:
            res = cipher.decrypt(data)

        return res

    encrypt = functools.partialmethod(_crypt, 'enc')
    decrypt = functools.partialmethod(_crypt, 'dec')


class SecurePassfile():
    def __init__(self, path):
        self.path = os.path.expanduser(path)
        path_sum = CryptoSum.new(data=path.encode('utf8'), digest_bytes=32)
        self.crypto = SecurePassfileCrypto(path_sum.hexdigest())
        self.content = self._get_passfile_content() or '{}'
        try:
            self.passwords = yaml.safe_load(self.content)
        except yaml.scanner.ScannerError as e:
            raise BadPassfile("Bad format: \n\t{}".format(e))

    def __str__(self):
        return self.content.decode('utf8')

    def _get_passfile_content(self):
        try:
            with open(self.path, 'rb') as f:
                metadata = f.read(self.crypto.metadata_size + 1)
                encrypted_passfile = f.read()
                self.crypto.set_metadata(metadata)
                return self.crypto.decrypt(encrypted_passfile)
        except FileNotFoundError:
            return None

    @ensure_utf8('decrypted_passfile')
    def create(self, decrypted_passfile, reset_key=True):
        if isinstance(decrypted_passfile, dict):
            decrypted_passfile = yaml.safe_dump(decrypted_passfile, default_flow_style=False)
        else:
            try:
                yaml.safe_load(decrypted_passfile)
            except yaml.scanner.ScannerError as e:
                print("Bad format: \n\t{}".format(e))

        if reset_key:
            self.crypto.reset_key()
        encrypted_passfile = self.crypto.encrypt(decrypted_passfile)
        with open(self.path, "wb") as f:
            f.write(self.crypto.get_metadata())
            f.write(b'\n')
            f.write(encrypted_passfile)

    def renew_key(self):
        self.create(self.content)

    def edit(self, name=None):
        temp_file_handle, temp_file_name = tempfile.mkstemp()
        try:
            os.close(temp_file_handle)
            if name:
                if name in self.passwords:
                    decrypted_passfile = yaml.safe_dump({name: self.passwords[name]}, default_flow_style=False)
                else:
                    decrypted_passfile = "{}:\n".format(name)
            else:
                decrypted_passfile = self.content

            @ensure_utf8('decrypted_passfile')
            def prepare_tmp_file(decrypted_passfile):
                with open(temp_file_name, 'wb') as f:
                    f.write(decrypted_passfile)
            prepare_tmp_file(decrypted_passfile)

            if shutil.which('edit'):
                os.system('edit text/plain:{}'.format(temp_file_name))
            elif 'EDITOR' in os.environ:
                os.system('$EDITOR {}'.format(temp_file_name))
            else:
                os.system('vi {}'.format(temp_file_name))

            with open(temp_file_name, 'rb') as f:
                new_decrypted_passfile = f.read()

            try:
                new_passwords = yaml.safe_load(new_decrypted_passfile)
            except yaml.scanner.ScannerError as e:
                raise BadPassfile("Bad format: \n\t{}".format(e))

            self.passwords.update(new_passwords)
            new_decrypted_passfile = yaml.safe_dump(self.passwords, default_flow_style=False)
            self.create(new_decrypted_passfile, reset_key=False)
        finally:
            if shutil.which('shred'):
                os.system("shred -n 3 -z -u {}".format(temp_file_name))
            else:
                os.remove(temp_file_name)


class DoType():
    def __init__(self, passwords, legacy_mode=False):
        if not have_xdo or legacy_mode:
            self.legacy = True
            self.type = self._type_legacy
            self.key = self._key_legacy
        else:
            self.legacy = False
            self.xdo = xdo.Xdo()
            self.window = self.xdo.get_active_window()
            self.type = self._type
            self.key = self._key

        self.passwords = passwords
        self.delay = 0
        self.key('ctrl')  # There is a "bug" in xcb (X11 client lib), the keymap is updated only after a first stoke https://bugs.freedesktop.org/show_bug.cgi?id=93701#c2

    def __setattr__(self, attr, val):
        if attr == 'delay':
            if val <= 12:
                return object.__setattr__(self, attr, 12)
            else:
                return object.__setattr__(self, attr, val)
        else:
            return object.__setattr__(self, attr, val)

    @ensure_utf8('text')
    def _type(self, text):
        self.xdo.enter_text_window(self.window, text, delay=self.delay * 1000)

    @ensure_utf8('key')
    def _key(self, key):
        self.xdo.send_keysequence_window(self.window, key, delay=self.delay * 1000)

    def _type_legacy(self, text):
        os.system("xdotool type --delay {} '{}'".format(self.delay, text))

    def _key_legacy(self, key):
        os.system("xdotool key --delay {} {};".format(self.delay, key))

    def execute(self, name):
        if self.passwords is not None and name in self.passwords:
            for action in self.passwords[name]:
                if isinstance(action, str):
                    self.type(action)
                elif isinstance(action, dict):
                    for k, v in action.items():
                        if k == 'type':
                            self.type(v)
                        elif k == 'key':
                            self.key(v)
                        elif k == 'wait':
                            time.sleep(int(v) / 1000.0)
                        elif k == 'delay':
                            self.delay = int(v)
                        else:
                            raise ValueError('Unknown action {}'.format(k))
                else:
                    raise TypeError('Unknown action type {}'.format(type(action)))
        else:
            print('{} not found'.format(name))


def generate_password(args):
    random_string = os.urandom(args.len)
    password = []
    tr, chars_table = {}, string.printable[:-5]  # we remove \t, \n, \r, \v, \f

    if args.no_quot:
        tr.update(str.maketrans('', '', "'\"`"))
    elif args.no_spec:
        tr.update(str.maketrans('', '', string.punctuation))
    if args.no_space:
        tr.update(str.maketrans('', '', ' '))

    chars_table = chars_table.translate(tr)
    mod = len(chars_table)
    for c in random_string:
        password.append(chars_table[c % mod])
    return ''.join(password)


def main(args):
    passfile = SecurePassfile(args.file)

    try:
        if args.generate:
            password = generate_password(args)
            print(password)
            #do = DoType("generated: '{}'".format(password), args.legacy)
            #do.execute('generated')
        elif args.init:
            if args.init_file:
                passfile.create(args.init_file.read())
            else:
                passfile.create('')
        elif args.edit:
            passfile.edit(name=args.name)
        elif args.print:
            if args.name:
                print(yaml.safe_dump({args.name: passfile.passwords[args.name]}, default_flow_style=False))
            else:
                print(passfile)
        elif args.name:
            do = DoType(passfile.passwords, args.legacy)
            do.execute(args.name)
        elif args.key:
            passfile.renew_key()

    except EncryptionKeyNotFound:
        print('No encryption key found, please recreate the pass file with --init option')
        sys.exit(1)
    except PassfileNotFound:
        print('The password file is not found, please create it with --init option')
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--edit", help="Edit the password file (opens a text editor)", action='store_true')
    parser.add_argument("-i", "--init", help="Init the password file as empty", action='store_true')
    parser.add_argument("--init-file", help="Init the password file with the content of the file passed as argument (in YAML format)", type=argparse.FileType('r'))
    parser.add_argument("-f", "--file", help="Path of the password file to use (in YAML format)", default='~/.passfile.yml.enc')
    parser.add_argument("-g", "--generate", help="Generate a password", action='store_true')
    parser.add_argument("--len", help="Length of a generated password (default 64)", default=64, type=int)
    parser.add_argument("--no-spec", help="No special chars in the generated password", default=False, action='store_true')
    parser.add_argument("--no-quot", help="No quotation marks in the generated password", default=False, action='store_true')
    parser.add_argument("--no-space", help="No space in the generated password", default=False, action='store_true')
    parser.add_argument("-k", "--key", help="Change the stored encryption key and re-encrypt the password file", action='store_true')
    parser.add_argument("-p", "--print", help="Print the password file", action='store_true')
    parser.add_argument("-l", "--legacy", help="Legacy mode (use xdotool instead of python3-xdo)", action='store_true')
    parser.add_argument("name", nargs='?', help="Name of the password to type")
    args = parser.parse_args()
    main(args)
    sys.exit(0)
