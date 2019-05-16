import asyncio
import hashlib
import unittest
import gzip
import json
import os
import getpass
import time
import sys
import concurrent.futures
import threading
import readline
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AESWrapper:
  class EncryptedData:
    def __init__(self, ciphertext=None, tag=None, nonce=None):
      self.ciphertext, self.tag, self.nonce = ciphertext, tag, nonce

    def bytes(self):
      return self.tag + b'nonce=' + self.nonce + b'ciphertext=' + self.ciphertext

    def __del__(self):
      del self.ciphertext, self.tag, self.nonce

  def __init__(self, key=None):
    if not key:
      key = get_random_bytes(32)
    elif type(key) is str:
      key = hashlib.sha256(str.encode(key)).digest()
    self.key = key

  def encrypt(self, data):
    cipher = AES.new(self.key, AES.MODE_EAX)
    nonce = cipher.nonce
    if type(data) is str:
      data = str.encode(data)
    data = gzip.compress(data)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return self.EncryptedData(ciphertext, tag, nonce)

  def decrypt(self, encrypted_data):
    cipher = AES.new(self.key, AES.MODE_EAX, nonce=encrypted_data.nonce)
    plaintext = cipher.decrypt(encrypted_data.ciphertext)
    try:
      cipher.verify(encrypted_data.tag)
      return gzip.decompress(plaintext)
    except ValueError:
      plaintext = None
    return plaintext

  def __eq__(self, other):
    return self.key == other.key

class EncryptionWrapper:
  def __init__(self, pw=None, key=None, db=None):
    self.pw = AESWrapper(pw) if pw else AESWrapper('password')
    self.key = AESWrapper(self.pw.decrypt(key)) if pw and key else AESWrapper()
    self.db = self.key.decrypt(db) if key and db else '{}'

  def __del__(self):
    del self.pw, self.key, self.db

  def encrypt(self):
    return self.key.encrypt(self.db), self.pw.encrypt(self.key.key)

class DataWrapper:
  def __init__(self, data=None):
    self.data = json.loads(data) if data else {}

  def __del__(self):
    self.data.clear()
    del self.data

  def upsert(self, name, value, overwrite=False):
    if name in self.data and not overwrite:
      return False
    self.data[name] = value
    return True

  def rm(self, name):
    if name not in self.data:
      return False
    del self.data[name]
    return True

  def find(self, substring):
    return list(filter(lambda data: data.find(substring) != -1, self.data.keys()))

  def dump(self):
    return json.dumps(self.data)

  def get(self, key):
    return self.data[key] if key in self.data else None

  def keys(self):
    return self.data.keys()

class FileManager:
  def __init__(self, base):
    if not os.path.exists(base):
      raise Exception("No base")
    self.db_filename = os.path.join(base, 'pwmgr.pwdb')
    self.key_filename = os.path.join(base, 'pwmgr.pwky')
    self.key = None
    self.db = None
    if os.path.exists(self.key_filename):
      with open(self.key_filename, 'rb') as f:
        self.key = f.read()
    if os.path.exists(self.db_filename):
      with open(self.db_filename, 'rb') as f:
        self.db = f.read()

  def get(self):
    encrypted_db = encrypted_key = None
    if self.key:
      tag, _, rest = self.key.partition(b'nonce=')
      nonce, _, ciphertext = rest.partition(b'ciphertext=')
      encrypted_key = AESWrapper.EncryptedData(ciphertext, tag, nonce)
    if self.db:
      tag, _, rest = self.db.partition(b'nonce=')
      nonce, _, ciphertext = rest.partition(b'ciphertext=')
      encrypted_db = AESWrapper.EncryptedData(ciphertext, tag, nonce)
    return encrypted_key, encrypted_db

  def save(self, pw, key, db):
    with open(self.key_filename, 'wb') as f:
      f.write(pw.encrypt(key.key).bytes())
    with open(self.db_filename, 'wb') as f:
      f.write(key.encrypt(db).bytes())


class Options:
  input_timeout = 300
  copy_timeout = 10

  @staticmethod
  def input(stack):
    stack.append(input('> '))

  @staticmethod
  async def do(fn):
    if not callable(fn):
      return fn
    return fn()

  @staticmethod
  def copy(data):
    if not data:
      return False
    os.system("echo '%s' | pbcopy" % data.replace("'", "\'"))
    def clear():
      time.sleep(Options.copy_timeout)
      os.system("echo '%s' | pbcopy" % '')
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
      executor.submit(clear)

  @staticmethod
  def change(field: str, ew: EncryptionWrapper):
    prev_pw = AESWrapper(getpass.getpass('Current Password: '))
    if prev_pw != ew.pw:
      return False
    if field == 'password':
      ew.pw = AESWrapper(Options.change_password())
    elif field == 'key':
      ew.key = AESWrapper()

  @staticmethod
  def change_password():
    new_pw1 = getpass.getpass('New Password: ')
    new_pw2 = getpass.getpass('Repeat Password: ')
    if new_pw1 != new_pw2:
      return False
    return new_pw1

  @staticmethod
  def set(dw, key, overwrite=False):
    value = Options.change_password()
    dw.upsert(key, value, overwrite)


async def main():
  pw = None
  try:
    pw = getpass.getpass('Password: ', None)
  except KeyboardInterrupt:
    exit()
  fm = FileManager(sys.argv[1] if len(sys.argv) > 1 else '')
  encrypted_key, encrypted_db = fm.get()
  ew = EncryptionWrapper(pw, encrypted_key, encrypted_db)
  del pw
  if ew.db is None:
    exit()
  dw = DataWrapper(ew.db)

  options = {
    'set': lambda key: Options.do(Options.set(dw, key)),
    'update': lambda key: Options.do(Options.set(dw, key, True)),
    'rm': lambda key: Options.do(dw.rm(key)),
    'copy': lambda key: Options.do(Options.copy(dw.get(key))),
    'get': lambda key: Options.do(dw.get(key)),
    'keys': lambda: Options.do(dw.keys()),
    'help': lambda: Options.do(options.keys()),
    'find': lambda substring: Options.do(dw.find(substring)),
    'change': lambda field: Options.do(Options.change(field, ew)),
  }

  stack = []
  while True:
    t = threading.Thread(target=Options.input, args=(stack,))
    t.daemon = True
    t.start()
    t.join(timeout=Options.input_timeout)
    if not len(stack):
      break
    option = stack.pop()
    command, _, arguments = option.partition(' ')
    if command not in options:
      break
    result = await options[command](*[arguments] if arguments else [])
    if result is not None:
      print(result)

  fm.save(ew.pw, ew.key, dw.dump())
  del dw, ew

if __name__ == '__main__':
  asyncio.run(main())

class TestPWMgr(unittest.TestCase):
  def test_overall(self):
    pw = 'password'
    pm = EncryptionWrapper(pw)
    encrypted_file, encrypted_key = pm.encrypt()
    pm2 = EncryptionWrapper(pw, encrypted_key, encrypted_file)
    self.assertEqual(pm2.db, b'{}')

  def test_add_and_remove(self):
    key, value = 'hi', 'there'
    dw = DataWrapper()
    dw.upsert(key, value)
    self.assertEqual(dw.get(key), value)
    dw.rm(key)
    self.assertEqual(dw.get(key), None)
