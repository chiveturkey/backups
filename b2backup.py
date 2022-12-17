#!/usr/bin/python3

"""Module providing backups to B2."""
import hashlib
import gc
import mmap
import os
import re
import sys
import tarfile
import time
from datetime import date
from datetime import datetime
from datetime import timedelta
import requests
import yaml
import nacl.secret
import nacl.utils


# Constants

CONFIG_FILE_NAME = 'config.yaml'
THISMONTH = '{:%Y%m}01'.format(date.today())
THREE_MONTHS_AGO = '{:%Y%m}01'.format(date.today() - timedelta(weeks=12))
BACKUP_DIRECTORY_DEFAULT = '.'
ENCRYPTED_FILE_PART_SIZE_DEFAULT = 1024
B2_AUTHORIZATION_URL = 'https://api.backblazeb2.com/b2api/v2/b2_authorize_account'
UPLOAD_ATTEMPTS = 6
BACKOFF_MODIFIER = 225
ACTIVE_PERIOD_BEGIN_HOUR = 20
ACTIVE_PERIOD_END_HOUR = 8
ESTIMATED_UPLOAD_TIME = 30
DISABLE_PAUSE = False
DEBUG = False


# Methods

def format_log(message):
    """Function formatting logs."""
    print(f'{datetime.now()}: {message}')

def banner(message):
    """Function printing banner log messages."""
    format_log('=' * len(message))
    format_log(message)
    format_log('=' * len(message))

def read_config(config_file_name=CONFIG_FILE_NAME):
    """Function reading config file."""
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
    """Function checking and updating secret_key in config."""
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
    """Function checking and updating volumes in config."""
    if 'volumes' in config:
        if not isinstance(config['volumes'], list):
            format_log('volumes in incorrect format.')
            sys.exit(1)
    else:
        format_log('volumes not found in config file.')
        sys.exit(1)

    return config

def check_and_update_b2(config):
    """Function checking b2 authentication and authorization values in config."""
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
    """Function checking and updating config."""
    if not isinstance(config, dict):
        format_log('Malformed config file.')
        sys.exit(1)
    else:
        config = check_and_update_secret_key(config)
        config = check_and_update_volumes(config)

        # Default 'backup_directory' to current directory.
        # TODO: Consider adding error checking on presence of legit 'backup_directory'.
        if 'backup_directory' not in config:
            config['backup_directory'] = backup_directory_default

        # Default 'encrypted_file_part_size' to 1M.
        if 'encrypted_file_part_size' not in config:
            config['encrypted_file_part_size'] = encrypted_file_part_size_default

        config = check_and_update_b2(config)

    return config


def create_archives(config, thismonth=THISMONTH):
    """Function creating local archives using tar and gzip."""
    format_log('Archiving volumes.')

    current_directory = os.getcwd()
    os.chdir(config['backup_directory'])

    for volume in config['volumes']:
        format_log(f'Archiving volume: {volume}')
        with tarfile.open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz",'w:gz') as tar:
            tar.add(volume)

    os.chdir(current_directory)

def list_files_matching(match_pattern, directory):
    """Function listing files that match a given Regular Expression"""
    file_list = []

    for filename in sorted(os.listdir(directory)):
        if re.search(match_pattern, filename):
            file_list.append(filename)

    return file_list

def list_local_archives(config):
    """Function listing local tar'd and gzip'd archives."""
    format_log('List local archived volumes.')
    file_list = list_files_matching(rf"\d+-({'|'.join(config['volumes'])})\.tar\.gz", config['backup_directory'])
    for filename in file_list:
        format_log(filename)

def encrypt_archives(config, thismonth=THISMONTH):
    """Function encrypting archives with PyNaCl.  Output encrypted files of size encrypted_file_part_size."""
    format_log('Encrypting volumes.')
    for volume in config['volumes']:
        with open(f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz", 'rb') as volume_file:
            with mmap.mmap(volume_file.fileno(), 0, access=mmap.ACCESS_READ) as volume_file_mmap:
                last_byte = volume_file_mmap.size() - 1
                part_number = 1
                while volume_file_mmap.tell() <= last_byte:
                    box = nacl.secret.SecretBox(config['secret_key'])
                    encrypted_volume_contents_part = box.encrypt(
                                                             volume_file_mmap.read(config['encrypted_file_part_size']))
                    with open(
                            f"{config['backup_directory']}/{thismonth}-{volume}.tar.gz.enc.part{part_number:03d}.sha1",
                            'w') as encrypted_volume_file_part_hash:
                        encrypted_volume_file_part_hash.write(checksum(encrypted_volume_contents_part))
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
    """Function listing local encrypted archives."""
    format_log('List local encrypted volumes.')
    file_list = list_files_matching(rf"\d+-({'|'.join(config['volumes'])})\.tar\.gz\.enc", config['backup_directory'])
    for filename in file_list:
        format_log(filename)

def decrypt_archives(config, thismonth=THISMONTH):
    """Function decrypting archives with PyNaCl.  Input encrypted file parts, and output decrypted archive."""
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

def checksum(byte_string):
    """Function computing a checksum on a string."""
    return hashlib.sha1(byte_string).hexdigest()

def b2_authorize_account(config, b2_authorization_url=B2_AUTHORIZATION_URL, debug=DEBUG):
    """Function authorizing B2 account."""
    response = requests.get(b2_authorization_url, auth=(config['b2_key_id'], config['b2_key_value']))
    if debug:
        format_log(response.text)

    if response.status_code == 200:
        format_log('Authorized account with B2.')
        config['api_url'] = response.json()['apiUrl']
        config['auth_token'] = response.json()['authorizationToken']
        return config

    format_log('Failed to authorize account with B2.')
    format_log(f'HTTP Status Code: {response.status_code}')
    # TODO: Should we have this exit, or would it be better to bubble up the error and retry?
    sys.exit(1)

def b2_list_files(config, prefix='', max_file_count=1000, debug=DEBUG):
    """Function listing files in a B2 bucket."""
    try:
        response = requests.post(f"{config['api_url']}/b2api/v2/b2_list_file_names",
                                 headers={'Authorization': config['auth_token']},
                                 data=f"{{\"bucketId\": \"{config['b2_bucket_id']}\", \
                                          \"maxFileCount\": {max_file_count}, \
                                          \"prefix\": \"{prefix}\"}}")
        if debug:
            format_log(response.text)

        if response.status_code == 200:
            files = []
            for file_json in response.json()['files']:
                files.append((file_json['fileName'], file_json['fileId']))
            return files

        format_log(f'HTTP Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as err:
        format_log(f"A ConnectionError occurred for b2_list_file_names: {err}")
    except:
        format_log('An unknown error occurred.')
        format_log(sys.exc_info())

    format_log('Failed to list files on B2.')
    return []

def b2_get_upload_url(api_url, auth_token, b2_bucket_id, debug=DEBUG):
    """Function getting upload URL for a B2 bucket."""
    try:
        response = requests.post(f"{api_url}/b2api/v2/b2_get_upload_url",
                                 headers={'Authorization': auth_token},
                                 data='{"bucketId": "%s"}' % b2_bucket_id)
        if debug:
            format_log(response.text)

        if response.status_code == 200:
            format_log('Got upload URL from B2.')
            upload_url = response.json()['uploadUrl']
            upload_auth_token = response.json()['authorizationToken']
            return upload_url, upload_auth_token

        format_log(f'HTTP Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as err:
        format_log(f"A ConnectionError occurred for {api_url}: {err}")
    except:
        format_log('An unknown error occurred.')
        format_log(sys.exc_info())

    format_log('Failed to get upload URL from B2.')
    return None, None

def b2_upload_file(volume, file_info, upload_url, upload_auth_token, debug=DEBUG):
    """Function interacting with B2 API to upload file to a B2 bucket."""
    try:
        response = requests.post(upload_url,
                                 headers={'Authorization': upload_auth_token,
                                          'X-Bz-File-Name': f"{volume}/{file_info['file_name']}",
                                          'Content-Type': 'application/octet-stream',
                                          'Content-Length': file_info['file_size'],
                                          'X-Bz-Content-Sha1': file_info['file_hash']},
                                 data=file_info['file_contents'])
        if debug:
            format_log(response.text)

        if response.status_code == 200:
            format_log(f"Uploaded {file_info['file_name']} to B2.")
            return True

        format_log(f'HTTP Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as err:
        format_log(f"A ConnectionError occurred for {file_info['file_name']}: {err}")
    except:
        format_log('An unknown error occurred.')
        format_log(sys.exc_info())

    format_log(f"Failed to upload {file_info['file_name']} to B2.")
    return False

def get_file_info(file_part_name, backup_directory):
    """Function gathering file info."""
    file_size = str(os.stat(f"{backup_directory}/{file_part_name}").st_size)
    file_hash = b''
    file_contents = b''
    with open(f"{backup_directory}/{file_part_name}.sha1", 'rb') as file_part_hash:
        file_hash = file_part_hash.read()
    with open(f"{backup_directory}/{file_part_name}", 'rb') as file_part:
        with mmap.mmap(file_part.fileno(), 0, access=mmap.ACCESS_READ) as file_part_mmap:
            file_contents = file_part_mmap.read()
    return {'file_name': file_part_name,
            'file_size': file_size,
            'file_hash': file_hash,
            'file_contents': file_contents}

def active_upload_period(check_time,
                         active_period_begin_hour=ACTIVE_PERIOD_BEGIN_HOUR,
                         active_period_end_hour=ACTIVE_PERIOD_END_HOUR):
    """Function determining whether upload execution is within active upload period."""
    if check_time.hour >= active_period_begin_hour:
        active_period_begin = datetime(check_time.year, check_time.month, check_time.day, active_period_begin_hour)
    else:
        active_period_begin = datetime(check_time.year, check_time.month, check_time.day - 1, active_period_begin_hour)

    active_period_end = datetime(check_time.year, check_time.month, active_period_begin.day + 1, active_period_end_hour)

    return bool(active_period_begin <= check_time < active_period_end)

def pause_if_out_of_upload_period(active_period_begin_hour=ACTIVE_PERIOD_BEGIN_HOUR,
                                  estimated_upload_time=ESTIMATED_UPLOAD_TIME):
    """Function pausing upload execution if outside of active upload period."""
    now = datetime.now()
    if not active_upload_period(now + timedelta(minutes=estimated_upload_time)):
        format_log(f'Outside of active upload period.  Sleeping until {active_period_begin_hour}:00.')
        time.sleep((datetime(now.year, now.month, now.day, active_period_begin_hour) - now).seconds)
        format_log('Inside active period.  Continuing upload.')
        return True

    return False

def upload_archive_file_part(volume,
                             file_part_name,
                             config,
                             upload_attempts=UPLOAD_ATTEMPTS,
                             backoff_modifier=BACKOFF_MODIFIER):
    """Function gathering file info and uploading file to B2 bucket."""
    file_info = get_file_info(file_part_name, config['backup_directory'])
    for i in range(upload_attempts):
        upload_url, upload_auth_token = b2_get_upload_url(config['api_url'],
                                                          config['auth_token'],
                                                          config['b2_bucket_id'])
        if upload_url is not None and upload_auth_token is not None:
            if b2_upload_file(volume, file_info, upload_url, upload_auth_token):
                return True

        # Exponential backoff.  Sleep after each attempt except for the last.
        if i < upload_attempts - 1:
            format_log(f'Backing off for {backoff_modifier * i**2} seconds.')
            time.sleep(backoff_modifier * i**2)

    format_log(f'Failed to upload {file_part_name} to B2 after {upload_attempts} tries.')
    return False

def upload_archive_files(config, thismonth=THISMONTH, disable_pause=DISABLE_PAUSE):
    """Function uploading archive files."""
    config = b2_authorize_account(config)
    format_log('Uploading volumes.')
    for volume in config['volumes']:
        format_log(f'Uploading volume: {volume}')
        for file_part_name in list_files_matching(rf"{thismonth}-{volume}\.tar\.gz\.enc.part\d+$",
                                                  config['backup_directory']):
            if not disable_pause and pause_if_out_of_upload_period():
                # Refresh auth_token after pause.
                config = b2_authorize_account(config)
            # TODO: Key off of return value of upload_archive_file_part.
            upload_archive_file_part(volume, file_part_name, config)

def verify_uploaded_files(config, thismonth=THISMONTH):
    """Function verifying that all files uploaded successfully."""
    format_log('Verifying uploaded volumes.')
    for volume in config['volumes']:
        files = b2_list_files(config, f'{volume}/{thismonth}')
        if files == []:
            format_log(f'{volume} not found on B2.')
            return False
        for file_part_name in list_files_matching(rf"{thismonth}-{volume}\.tar\.gz\.enc.part\d+$",
                                                  config['backup_directory']):
            file_found = False
            for file_info in files:
                if file_info[0] == f'{volume}/{file_part_name}':
                    file_found = True
            if not file_found:
                format_log(f'{file_part_name} not found on B2.')
                return False
    return True

def list_local_archive_file_parts_from_date(config, archive_file_part_date):
    """Function listing local encrypted archive file parts from a particular date."""
    format_log(f'List local encrypted archive file parts from {archive_file_part_date}.')
    file_list = list_files_matching(rf"{archive_file_part_date}-({'|'.join(config['volumes'])})\.tar\.gz\.enc.part",
                                    config['backup_directory'])
    for filename in file_list:
        format_log(filename)
    return file_list

def delete_current_local_archive_file_parts(config, thismonth=THISMONTH):
    """Function deleting current local encrypted archive file parts."""
    format_log('Delete old local encrypted archive file parts.')
    for filename in list_local_archive_file_parts_from_date(config, thismonth):
        os.remove(f"{config['backup_directory']}/{filename}")

def list_local_archives_from_date(config, archive_file_date):
    """Function listing local tar'd and gzip'd archives from a particular date."""
    format_log(f'List local archived volumes from {archive_file_date}.')
    file_list = list_files_matching(rf"{archive_file_date}-({'|'.join(config['volumes'])})\.tar\.gz",
                                    config['backup_directory'])
    for filename in file_list:
        format_log(filename)
    return file_list

def delete_old_local_archive_files(config, old_file_date=THREE_MONTHS_AGO):
    """Function deleting old local archive files."""
    format_log('Delete old local archived volume files.')
    for filename in list_local_archives_from_date(config, old_file_date):
        os.remove(f"{config['backup_directory']}/{filename}")

def b2_delete_file(filename, file_id, api_url, auth_token, debug=DEBUG):
    """Function deleting a file from b2."""
    try:
        response = requests.post(f"{api_url}/b2api/v2/b2_delete_file_version",
                                 headers={'Authorization': auth_token},
                                 data=f'{{"fileName": "{filename}", "fileId": "{file_id}"}}')
        if debug:
            format_log(response.text)

        if response.status_code == 200:
            format_log(f"Deleted {filename} from B2.")
            return True

        format_log(f'HTTP Status Code: {response.status_code}')
    except requests.exceptions.ConnectionError as err:
        format_log(f"A ConnectionError occurred for {filename}: {err}")
    except:
        format_log('An unknown error occurred.')
        format_log(sys.exc_info())

    format_log(f"Failed to delete {filename} from B2.")
    return False

def b2_delete_old_files(config, old_file_date=THREE_MONTHS_AGO):
    """Function deleting old files from B2."""
    format_log('Deleting old volumes from B2.')
    for volume in config['volumes']:
        format_log(f'Deleting volume: {volume}/{old_file_date}')
        files = b2_list_files(config, f'{volume}/{old_file_date}')
        if files == []:
            format_log(f'Unable to delete.  There are no old volumes matching: {volume}/{old_file_date}')
        else:
            for file_info in files:
                # TODO: Key off of return value of b2_delete_file.
                b2_delete_file(file_info[0], file_info[1], config['api_url'], config['auth_token'])

def verify_and_cleanup(config):
    """Function verifying uploads and deleting old files."""
    config = b2_authorize_account(config)

    if verify_uploaded_files(config):
        delete_current_local_archive_file_parts(config)
    else:
        format_log('Failed to verify all uploaded files.  Not deleting local archive file parts.')

    b2_delete_old_files(config)
    delete_old_local_archive_files(config)


# Main

def main():
    """Function providing main functionality for backup module."""
    banner('Monthly archival backup.')

    config = read_config()
    config = check_and_update_config(config)
    create_archives(config)
    list_local_archives(config)
    encrypt_archives(config)
    list_local_encrypted_archives(config)

    upload_archive_files(config)

    # TODO: Uncomment when ready.
    # verify_and_cleanup(config)

main()
# configuration = read_config()
# configuration = check_and_update_config(configuration)
# decrypt_archives(configuration)
# configuration = b2_authorize_account(configuration)
# upload_archive_files(configuration)
# verify_uploaded_files(configuration)
# format_log('Finished.')
# verify_and_cleanup(configuration)
