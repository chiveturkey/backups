#!/usr/bin/python3

'''Module providing backups to B2.'''
import gc
import mmap
import os
import re
import sys
import tarfile
from datetime import date
from datetime import datetime
import requests
import yaml
import nacl.secret
import nacl.utils


# Constants

CONFIG_FILE_NAME = 'config.yaml'
THISMONTH = '{:%Y%m}01'.format(date.today())
BACKUP_DIRECTORY_DEFAULT = '.'
ENCRYPTED_FILE_PART_SIZE_DEFAULT = 1024
B2_AUTHORIZATION_URL = 'https://api.backblazeb2.com/b2api/v2/b2_authorize_account'
DEBUG = False


# Methods

def format_log(message):
    '''Function formatting logs.'''
    print(f'{datetime.now()}: {message}')

def banner(message):
    '''Function printing banner log messages.'''
    format_log('=' * len(message))
    format_log(message)
    format_log('=' * len(message))

def read_config(config_file_name=CONFIG_FILE_NAME):
    '''Function reading config file.'''
    format_log(f'Reading config file: {config_file_name}.')

    # If config_file_name exists, then use configuration values found there.  Otherwise,
    # print an error.
    if os.path.isfile(config_file_name):
        # Attempt to open file.  Otherwise, print an error.
        try:
            with open(config_file_name) as config_file:
                config = yaml.safe_load(config_file)

            return config
        except FileNotFoundError:
            format_log(f'File {config_file_name} not found.')
            sys.exit(1)
    else:
        format_log(f'File {config_file_name} not found.')
        sys.exit(1)

def check_and_update_secret_key(config):
    '''Function checking and updating secret_key in config.'''
    if 'secret_key' in config:
        if isinstance(config['secret_key'], str):
            # PyNaCl requires secret_key of type bytes.
            config['secret_key'] = bytes(config['secret_key'], 'utf-8')
        else:
            format_log('secret_key in incorrect format.')
            sys.exit(1)
    else:
        format_log('secret_key not found in config file.')
        sys.exit(1)

    return config

def check_and_update_volumes(config):
    '''Function checking and updating volumes in config.'''
    if 'volumes' in config:
        if not isinstance(config['volumes'], list):
            format_log('volumes in incorrect format.')
            sys.exit(1)
    else:
        format_log('volumes not found in config file.')
        sys.exit(1)

    return config

def check_and_update_b2(config):
    '''Function checking b2 authentication and authorization values in config.'''
    if 'b2_key_id' not in config:
        config['b2_key_id'] = ''

    if 'b2_key_value' not in config:
        config['b2_key_value'] = ''

    if 'b2_bucket_id' not in config:
        config['b2_bucket_id'] = ''

    return config

def check_and_update_config(config,
                            backup_directory_default=BACKUP_DIRECTORY_DEFAULT,
                            encrypted_file_part_size_default=ENCRYPTED_FILE_PART_SIZE_DEFAULT):
    '''Function checking and updating config.'''
    if not isinstance(config, dict):
        format_log('Malformed config file.')
        sys.exit(1)
    else:
        config = check_and_update_secret_key(config)
        config = check_and_update_volumes(config)

        # Default 'backup_directory' to current directory.
        if 'backup_directory' not in config:
            config['backup_directory'] = backup_directory_default

        # Default 'encrypted_file_part_size' to 1M.
        if 'encrypted_file_part_size' not in config:
            config['encrypted_file_part_size'] = encrypted_file_part_size_default

        config = check_and_update_b2(config)

    return config


def create_archives(config, thismonth=THISMONTH):
    '''Function creating local archives using tar and gzip.'''
    format_log('Archiving volumes.')

    current_directory = os.getcwd()
    os.chdir(config['backup_directory'])

    for volume in config['volumes']:
        with tarfile.open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz",'w:gz') as tar:
            tar.add(volume)

    os.chdir(current_directory)

def list_files_matching(match_pattern, directory):
    '''Function listing files that match a given Regular Expression'''
    # TODO: Consider adding error checking on presence of legit 'backup_directory', and/or add
    # reasonable default that is set if config file value doesn't exist.  Or fail if config value
    # doesn't exist...?
    for filename in sorted(os.listdir(directory)):
        if re.search(match_pattern, filename):
            format_log(filename)

def list_local_archives(config):
    '''Function listing local tar'd and gzip'd archives.'''
    format_log('List local archived volumes.')
    list_files_matching(rf"\d+-({'|'.join(config['volumes'])})\.tar\.gz", config['backup_directory'])

def encrypt_archives(config, thismonth=THISMONTH):
    '''Function encrypting archives with PyNaCl.  Output encrypted files of size encrypted_file_part_size.'''
    format_log('Encrypting volumes.')
    for volume in config['volumes']:
        with open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz", 'rb') as volume_file:
            with mmap.mmap(volume_file.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                last_byte = mm.size() - 1
                volume_contents_part = b' '
                part_number = 1
                while mm.tell() <= last_byte:
                    box = nacl.secret.SecretBox(config['secret_key'])
                    encrypted_volume_contents_part = box.encrypt(mm.read(config['encrypted_file_part_size']))
                    with open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz.enc.part{part_number:03d}",
                              'wb') as encrypted_volume_file_part:
                        encrypted_volume_file_part.write(encrypted_volume_contents_part)
                    # HACKTAG: I suspect this is really awful.  :D  How else could we do it?
                    # Experimenting with pseudo-manual memory management.  Delete
                    # encrypted_volume_contents_part variable, and force garbage collection.
                    del encrypted_volume_contents_part
                    gc.collect()
                    part_number += 1

def list_local_encrypted_archives(config):
    '''Function listing local encrypted archives.'''
    format_log('List local encrypted volumes.')
    list_files_matching(rf"\d+-({'|'.join(config['volumes'])})\.tar\.gz\.enc", config['backup_directory'])

def decrypt_archives(config, thismonth=THISMONTH):
    '''Function decrypting archives with PyNaCl.  Input encrypted file parts, and output decrypted archive.'''
    format_log('Decrypting volumes.')
    for volume in config['volumes']:
        part_number = 1
        while os.path.isfile(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz.enc.part{part_number:03d}"):
            with open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz.enc.part{part_number:03d}",
                      'rb') as encrypted_volume_file_part:
                encrypted_volume_contents_part = encrypted_volume_file_part.read()
                box = nacl.secret.SecretBox(config['secret_key'])
                volume_contents_part = box.decrypt(encrypted_volume_contents_part)
                # HACKTAG: I suspect this is really awful.  :D  How else could we do it?
                # Experimenting with pseudo-manual memory management.  Delete
                # encrypted_volume_contents_part variable, and force garbage collection.
                del encrypted_volume_contents_part
                gc.collect()
                with open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz", 'ab') as volume_file:
                    volume_file.write(volume_contents_part)
                # HACKTAG: I suspect this is really awful.  :D  How else could we do it?
                # Experimenting with pseudo-manual memory management.  Delete
                # volume_contents_part variable, and force garbage collection.
                del volume_contents_part
                gc.collect()
            part_number += 1

def checksum(config, thismonth=THISMONTH):
    '''Function computing a checksum on a string.'''

def b2_authorize_account(config, b2_authorization_url=B2_AUTHORIZATION_URL):
    '''Function authorizing B2 account.'''
    response = requests.get(b2_authorization_url, auth=(config['b2_key_id'], config['b2_key_value']))
    print(response.text)
    if response.status_code == 200:
        format_log('Authorized account with B2.')
        config['api_url'] = response.json()['apiUrl']
        config['auth_token'] = response.json()['authorizationToken']
        return config
    else:
        format_log('Failed to authorize account with B2.')
        format_log(f'HTTP Status Code: {response.status_code}')
        sys.exit(1)

def b2_list_files(config):
    '''Function listing files in a B2 bucket.'''
    response = requests.post(f"{config['api_url']}/b2api/v2/b2_list_file_names",
                             headers={'Authorization': config['auth_token']},
                             data='{"bucketId": "%s"}' % config['b2_bucket_id'])
    print(response.text)


# Main

def main():
    '''Function providing main functionality for backup module.'''
    banner('Monthly archival backup.')

    config = read_config()
    config = check_and_update_config(config)
    create_archives(config)
    list_local_archives(config)
    encrypt_archives(config)
    list_local_encrypted_archives(config)

main()
# configuration = read_config()
# configuration = check_and_update_config(configuration)
# print(configuration)
# encrypt_archives()
# decrypt_archives(configuration)
# configuration = b2_authorize_account(configuration)
# b2_list_files(configuration)
