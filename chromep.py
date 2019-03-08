import sqlite3, os, binascii, subprocess, base64, operator
import tempfile, shutil, glob, hmac, struct, itertools

###Big thanks to @mitsuhiko https://github.com/mitsuhiko/python-pbkdf2 for the below function pbkdf2_bin###
def pbkdf2_bin(hash_fxn, password, salt, iterations, keylen=16):
    _pack_int = struct.Struct('>I').pack
    hashfunc = sha1
    mac = hmac.new(password, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = itertools.starmap(operator.xor, itertools.izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]
###Big thanks to @mitsuhiko https://github.com/mitsuhiko/python-pbkdf2 for the above function pbkdf2_bin###

try:
    from hashlib import pbkdf2_hmac
except ImportError:
    #python version not available (Python <2.7.8, macOS < 10.11)
    #use @mitsuhiko's pbkdf2 method
    pbkdf2_hmac = pbkdf2_bin
    from hashlib import sha1

login_data_path = raw_input("Input 'Login Data' file path: ")
cc_data_path = raw_input("Input 'Web Data' file path: ")
chrome_data = glob.glob(login_data_path) + glob.glob(cc_data_path)
safe_storage_key = raw_input("Input Safe Storage Key: ")
print safe_storage_key
safe_storage_key = safe_storage_key.replace('\n', '')

def get_cc(cc_num):
    cc_dict = {3: 'AMEX', 4: 'Visa', 5: 'Mastercard', 6: 'Discover'}
    try:
        return cc_dict[cc_num[0]]
    except KeyError:
        return "Unknown Card Issuer"

def chrome_decrypt(encrypted, iv, key): #AES decryption using the PBKDF2 key and 16x ' ' IV, via openSSL (installed on OSX natively)
    hex_key = binascii.hexlify(key)
    hex_enc_password = base64.b64encode(encrypted[3:])
    try: #send any error messages to /dev/null to prevent screen bloating up
        decrypted = subprocess.check_output("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null" % (iv, hex_key, hex_enc_password), shell=True)
    except Exception as e:
        decrypted = 'ERROR retrieving password'
    return decrypted

def chrome_process(safe_storage_key, chrome_data):
    iv = ''.join(('20',) * 16) #salt, iterations, iv, size - https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
    key = pbkdf2_hmac('sha1', safe_storage_key, b'saltysalt', 1003)[:16]
    copy_path = tempfile.mkdtemp() #work around for locking DB
    with open(chrome_data, 'r') as content:
        dbcopy = content.read()
    with open('%s/chrome' % copy_path, 'w') as content:
        content.write(dbcopy) #if chrome is open, the DB will be locked, so get around by making a temp copy
    database = sqlite3.connect('%s/chrome' % copy_path)
    if 'Web Data' in chrome_data:
        sql = 'select name_on_card, card_number_encrypted, expiration_month, expiration_year from credit_cards'
    else:
        sql = 'select username_value, password_value, origin_url, submit_element from logins'
    decrypted_list = []
    with database:
        for values in database.execute(sql):
            #values will be (name_on_card, card_number_encrypted, expiration_month, expiration_year) or (username_value, password_value, origin_url, submit_element)
            if values[0] == '' or (values[1][:3] != b'v10'): #user will be empty if they have selected "never" store password
                continue
            else:
                decrypted_list.append((str(values[2]).encode('ascii', 'ignore'), values[0].encode('ascii', 'ignore'), str(chrome_decrypt(values[1], iv, key)).encode('ascii', 'ignore'), values[3]))
    shutil.rmtree(copy_path)
    return decrypted_list

def chrome():
    for profile in chrome_data:
        for i, x in enumerate(chrome_process(safe_storage_key, "%s" % profile)):
            if 'Web Data' in profile:
                if i == 0:
                    print "%sCredit Cards for Chrome Profile%s -> [%s%s%s]" % ('\033[92m', '\033[0m', '\033[95m', profile.split('/')[-2], '\033[0m')
                print "   %s[%s]%s %s%s%s\n\t%sCard Name%s: %s\n\t%sCard Number%s: %s\n\t%sExpiration Date: %s%s/%s" % ('\033[32m', (i+1), '\033[0m', '\033[1m', get_cc(x[2]), '\033[0m', '\033[32m', '\033[0m', x[1], '\033[32m', '\033[0m', x[2], '\033[32m', '\033[0m', x[0], x[3])
            else:
                if i == 0:
                    print "%sPasswords for Chrome Profile%s -> [%s%s%s]" % ('\033[92m', '\033[0m', '\033[95m', profile.split('/')[-2], '\033[0m')
                print "   %s[%s]%s %s%s%s\n\t%sUser%s: %s\n\t%sPass%s: %s" % ('\033[32m', (i + 1), '\033[0m', '\033[1m', x[0], '\033[0m', '\033[32m', '\033[0m', x[1], '\033[32m', '\033[0m', x[2])

if __name__ == '__main__':
    chrome()
