#!/usr/bin/python3
#
# pfaudit.py - Detect changes in a pfSense firewall configuration
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org/)
# Feel free to use the code, but please share the changes you've made
#

import os
import sys
import xmltodict
import json
import itertools
import paramiko
import io
import hashlib
import datetime
import argparse
import base64
import tempfile
import collections
import logging

from optparse import OptionParser
from copy import deepcopy
from cryptography.fernet import Fernet

verbose_mode = False
json_output = False
log_file = None
changes_list = []

def load_ssh_key(f, p=None):

    ''' Load a SSH key
        f = SSH private key file
        p = Key passphrase
    '''

    try:
        with open(f, 'r') as key_file:
            key_data = key_file.read().strip()
    except IOError as e:
        print(f"[ERROR] Cannot read SSH key file: {e}")
        sys.exit(1)
        
    private_key_file = io.StringIO(key_data)
    
    try:
        # First, try to load it as a modern Ed25519 key (most likely)
        key = paramiko.Ed25519Key.from_private_key(private_key_file, password=p)
    except Exception:
        # If it fails, reset the file pointer and try old-school RSA
        private_key_file.seek(0)
        try:
            key = paramiko.RSAKey.from_private_key(private_key_file, password=p)
        except Exception:
            # Finally, try ECDSA
            private_key_file.seek(0)
            key = paramiko.ECDSAKey.from_private_key(private_key_file, password=p)
            
    return key
def get_encryption_key():
    ''' Generates or loads a secure Fernet encryption key 
        for local cache files.
    '''
    key_file = ".pfaudit_cache.key"
    if not os.path.exists(key_file):
        # Generate a new secure key and save it
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        # Lock down file permissions (read/write for owner only)
        os.chmod(key_file, 0o600) 
    else:
        # Load existing key
        with open(key_file, 'rb') as f:
            key = f.read()
    return key

def encrypt_config(f, d):
    ''' Encrypt a config file string with AES (Fernet)
        and save it to disk.
    '''
    key = get_encryption_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(d.encode('utf-8'))
    
    try:
        with open(f, 'wb') as out_file:
            out_file.write(encrypted_data)
        os.chmod(f, 0o600) # Lock down the cache file permissions
        return True
    except IOError as e:
        print(f"[ERROR] Cannot save encrypted config cache: {e}")
        return False

def decrypt_config(f):
    ''' Decrypt a local config cache file and return the XML content.
        Returns unencrypted data (bytes) or None if file doesn't exist.
    '''
    if not os.path.exists(f):
        return None
        
    key = get_encryption_key()
    fernet = Fernet(key)
    
    try:
        with open(f, 'rb') as in_file:
            encrypted_data = in_file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        print(f"[ERROR] Cannot decrypt local cache (key mismatch or corrupt file): {e}")
        return None
def log(m):

    ''' Log a message
        TODO: Add more logging capabilities
    '''

    if verbose_mode:
        sys.stderr.write(m + "\n")

def list_to_dict(l):

    ''' Conver a Python list into a dict
    '''

    return dict(zip(map(str, range(len(l))), l))

def compare_dicts(d1, d2, ctx="/"):

    ''' Compare two ordered dicts for changes (new & old config)
    '''

    global changes_list

    now = datetime.datetime.now().isoformat()
    log("Changes in %s" % ctx)
    for k in d1:
        if k not in d2:
            log("Key '%s' removed from config" % k)
            d = deepcopy(d1)
            d['path'] = ctx
            d['action'] = "updated"
            d['timestamp'] = now
            changes_list.append(d)
    for k in d2:
        if k not in d1:
            log("Key '%s' added to config" % k)
            d = deepcopy(d2)
            d['path'] = ctx
            d['action'] = "added"
            d['timestamp'] = now
            changes_list.append(d)
            continue
        if d2[k] != d1[k]:
            if type(d2[k]) not in (dict, list, collections.OrderedDict):
                log("Key '%s' changed to '%s'" % (k,str(d2[k])))
                d = deepcopy(d2)
                d['path'] = ctx
                d['action'] = "updated"
                d['timestamp'] = now
                changes_list.append(d)
            else:
                if type(d1[k]) != type(d2[k]):
                    log("Key '%s' changed to '%s':" % (k,str(d2[k])))
                    d = deepcopy(d2)
                    d['path'] = ctx
                    d['action'] = "updated"
                    d['timestamp'] = now
                    changes_list.append(d)
                    continue
                else:
                    if type(d2[k]) == dict or type(d2[k]) == collections.OrderedDict:
                        compare_dicts(d1[k], d2[k], ctx + k + "/")
                        continue
                    elif type(d2[k]) == list:
                        compare_dicts(list_to_dict(d1[k]), list_to_dict(d2[k]), ctx + k + "/")
    return

def process_firewall(host, user, key, passphrase):

    ''' Search for changes in a firewall configuration
    '''

    global json_output
    global log_file

    log("Connecting to ssh://%s@%s" % (user, host))
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        ssh.connect(host, username=user, pkey=load_ssh_key(key, passphrase))
    except Exception as e:
        print(f"\n[SSH CONNECTION ERROR] Failed to connect: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
#    temp_file = tempfile.mktemp()
    fd, temp_file = tempfile.mkstemp()
    os.close(fd)
    log("Dumping configuration to %s" % temp_file)
    try:
        sftp = ssh.open_sftp()
        sftp.get('/cf/conf/config.xml', temp_file)
        sftp.close()

    except Exception as e:
        print(f"\n[CRITICAL ERROR] The script crashed here: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    log("Processing %s" % temp_file)
    with open(temp_file) as xml_file:
        data = xml_file.read()
        data_dict_new = xmltodict.parse(data)
        hash_object = hashlib.sha256(str(data_dict_new).encode())
        sha256_hash_new = hash_object.hexdigest()
    xml_file.close()
    hostname = data_dict_new['pfsense']['system']['hostname']
    log("Firewall hostname: %s" % hostname)
    d = decrypt_config(host + ".conf")
    if d == None:
        # Cannot read old config, 1st execution?
        log("Cannot load the previous configuration")
        data_dict = data_dict_new
    else:
        data_dict = xmltodict.parse(d)

    hash_object = hashlib.sha256(str(data_dict).encode())
    sha256_hash = hash_object.hexdigest()

    rc = 0
    log("Writing encrypted configuration to %s.conf" % host)
    if encrypt_config(host + ".conf", data) == True:
        log("Comparing configurations: Old SHA256: %s, New SHA256: %s" % (sha256_hash, sha256_hash_new))
        if sha256_hash != sha256_hash_new:
            xml_dict = data_dict;
            xml_dict_new = data_dict_new

            compare_dicts(xml_dict, xml_dict_new)

            if json_output:
                try:
                    log("Dumping JSON events to %s" % log_file if log_file else "Dumping JSON events to stdout")
                    fh = open(log_file, 'a') if log_file else sys.stdout
                    # Dedup changes
                    new_list = []
                    for i in changes_list:
                        if i not in new_list:
                            new_list.append(i)
                    for l in new_list:
                        fh.write(json.dumps(l) + "\n")
                except:
                    print("Cannot dump JSON data")
                    rc = 1

                try:
                    fh.close()
                except:
                    pass
        else:
            log("No configuration change detected")
            rc = 1
    else:
        print("Cannot save configuration.")
        rc = 1

    os.unlink(temp_file)
    ssh.close()
    return rc

def main(argv):

    global verbose_mode
    global json_output
    global changes_list
    global log_file

    parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
    parser.add_option('-u', '--user', dest='ssh_user', type='string', \
    		help='SSH user')
    parser.add_option('-H', '--host', dest='ssh_host', type='string', \
    		help='Firewall FQDN or IP address (multiple hosts separated with commas)')
    parser.add_option('-k', '--key', dest='key_file', type='string', \
    		help='SSH RSA private key')
    parser.add_option('-p', '--passphrase', dest='key_passphrase', type='string', \
    		help='SSH key passphrase')
    parser.add_option('-j', '--json', action='store_true', dest='json_output', \
			help='Generate JSON logfile')
    parser.add_option('-l', '--log', dest='log_file', type='string', \
            help='Local log file (default: stdout)')
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', \
			help='Verbose output')
    (options, args) = parser.parse_args()

    if options.verbose:
        verbose_mode = True

    if options.json_output:
        json_output = True

    if options.log_file:
        log_file = options.log_file

    if not options.ssh_host:
        print("No pfSense host provided.")
        sys.exit(1)

    if not options.ssh_user:
        print("No SSH user provided.")
        sys.exit(1)

    if not options.key_file:
        print("No SSH key provided.")
        sys.exit(1)

    if options.key_passphrase not in locals():
        options.key_passphrase = None

    rc = 0
    for host in options.ssh_host.split(','):
        rc = process_firewall(host, options.ssh_user, options.key_file, options.key_passphrase)

    sys.exit(rc)

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(1)
