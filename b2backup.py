#!/usr/bin/python3

'''Module providing backups to B2.'''
import gc
import os
import re
import sys
import tarfile
from datetime import date
from datetime import datetime
import yaml
import nacl.secret
import nacl.utils


# Constants

CONFIG_FILE_NAME = 'config.yaml'
THISMONTH = '{:%Y%m}01'.format(date.today())
BACKUP_DIRECTORY_DEFAULT = '.'
ENCRYPTED_FILE_PART_SIZE_DEFAULT = 1024
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
            volume_contents_part = b' '
            part_number = 1
            while volume_contents_part != b'':
                volume_contents_part = volume_file.read(config['encrypted_file_part_size'])
                if volume_contents_part != b'':
                    box = nacl.secret.SecretBox(config['secret_key'])
                    encrypted_volume_contents_part = box.encrypt(volume_contents_part)
                    # HACKTAG: I suspect this is really awful.  :D  How else could we do it?
                    # Experimenting with pseudo-manual memory management.  Reset
                    # volume_contents_part variable, and force garbage collection.
                    volume_contents_part = b' '
                    gc.collect()
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
# encrypt_archives()
# decrypt_archives()
# configuration = read_config()
# configuration = check_and_update_config(configuration)
# print(configuration)
