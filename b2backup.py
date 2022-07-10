#!/usr/bin/python3

'''Module providing backups to B2.'''
import os
# import pprint
import re
import tarfile
from datetime import date
from datetime import datetime
import nacl.secret
import nacl.utils


# Constants

VOLUMES = 'testdir1,testdir2'
THISMONTH = '{:%Y%m}01'.format(date.today())
# TODO: This needs to be read in at run time.  Making it a constant for now.
SECRET_KEY = b'abcdefghijklmnopqrstuvwxyz012345'
DEBUG = False

# Methods

def format_log(message):
    '''Function formatting logs.'''
    print(datetime.now().isoformat(' '))
    print()
    print('=' * len(message))
    print(message)
    print('=' * len(message))
    print()

# TODO: Retool this to ensure it works in the correct directories.
def create_archives(volumes=VOLUMES, thismonth=THISMONTH):
    '''Function creating local archives using tar and gzip.'''
    format_log('Archiving volumes.')
    for volume in volumes.split(','):
        with tarfile.open(f'{thismonth}-{volume}.tar.gz','w:gz') as tar:
            tar.add(volume)

def list_files_matching(match_pattern):
    for filename in os.listdir():
        if re.search(match_pattern, filename):
            print(filename)
    print()

def list_local_archives():
    '''Function listing local tar'd and gzip'd archives.'''
    format_log('List local archived volumes.')
    list_files_matching(r'.*\.tar\.gz')

def encrypt_archives(volumes=VOLUMES, thismonth=THISMONTH, key=SECRET_KEY):
    '''Encrypt archives with PyNaCl.'''
    format_log('Encrypting volumes.')
    for volume in volumes.split(','):
        with open(f'{thismonth}-{volume}.tar.gz', 'rb') as volume_file:
            # TODO: This is a naive first pass.  It reads the *entire* contents of the file at
            # once.  If the file is large, it will fill up available RAM very quickly.
            volume_contents = volume_file.read()
            # volume_contents = b'This is some test text to encrypt.'
            box = nacl.secret.SecretBox(key)
            encrypted_volume_contents = box.encrypt(volume_contents)
            # print(encrypted_volume_contents)
            with open(f'{thismonth}-{volume}.tar.gz.enc', 'wb') as encrypted_volume_file:
                encrypted_volume_file.write(encrypted_volume_contents)

def list_local_encrypted_archives():
    '''Function listing local encrypted archives.'''
    format_log('List local encrypted volumes.')
    list_files_matching(r'.*\.tar\.gz\.enc')

def decrypt_archives(volumes=VOLUMES, thismonth=THISMONTH, key=SECRET_KEY):
    '''Decrypt archives with PyNaCl.'''
    format_log('Decrypting volumes.')
    for volume in volumes.split(','):
        with open(f'{thismonth}-{volume}.tar.gz.enc', 'rb') as encrypted_volume_file:
            # TODO: This is a naive first pass.  It reads the *entire* contents of the file at
            # once.  If the file is large, it will fill up available RAM very quickly.
            encrypted_volume_contents = encrypted_volume_file.read()
            box = nacl.secret.SecretBox(key)
            volume_contents = box.decrypt(encrypted_volume_contents)
            with open(f'{thismonth}-{volume}.tar.gz', 'wb') as volume_file:
                volume_file.write(volume_contents)

# def split_file():
#     with open()

# Main

def main():
    '''Function providing main functionality for backup module.'''
    format_log('Monthly archival backup.')

    create_archives()
    list_local_archives()
    encrypt_archives()
    list_local_encrypted_archives()

# main()
# encrypt_archives()
# decrypt_archives()

# NOTES:

# File Read/Write Testing:

# >>> f = open('bluh', 'wb')
# >>> f.write(b'abcdefghijklmnopqrstuvwxyz0123456789\n')
# 37
# >>> f.write(b'abcdefghijklmnopqrstuvwxyz0123456789\n')
# 37
# >>> f.write(b'abcdefghijklmnopqrstuvwxyz0123456789\n')
# 37
# >>> f.write(b'abcdefghijklmnopqrstuvwxyz0123456789\n')
# 37
# >>> f.write(b'abcdefghijklmnopqrstuvwxyz0123456789\n')
# 37
# >>> f.close()
# >>> f = open('bluh', 'rb')
# >>> f.read()
# b'abcdefghijklmnopqrstuvwxyz0123456789\nabcdefghijklmnopqrstuvwxyz0123456789\nabcdefghijklmnopqrstuvwxyz0123456789\nabcdefghijklmnopqrstuvwxyz0123456789\nabcdefghijklmnopqrstuvwxyz0123456789\n'
# >>> f.close()
# >>> f = open('bluh', 'rb')
# >>> f.readline()
# b'abcdefghijklmnopqrstuvwxyz0123456789\n'
# >>> f.readline()
# b'abcdefghijklmnopqrstuvwxyz0123456789\n'
# >>> f.close()
