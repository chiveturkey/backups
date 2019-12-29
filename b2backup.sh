#!/usr/bin/bash

# Constants


# Change directory to the directory the application is running in, to allow the relative path to
# backups.config.
#
# HACKTAG: Using a relative path to read config files is error prone.
# See http://mywiki.wooledge.org/BashFAQ/028
#
# In particular, "[i]t is important to realize that in the general case, this problem has no
# solution. Any approach you might have heard of, and any approach that will be detailed below, has
# flaws and will only work in specific cases."  Since this script is for personal use, and since I
# use it in a fairly limited fashion, I think this is an acceptable risk.  For more general use on
# diverse systems, it would be preferable to use an absolute path for backups.config.
cd "${BASH_SOURCE%/*}/" || exit

# Read in config file.
while IFS='=' read -r name value
do
  export $name=${value//\'/}
done < backups.config

# Convert volumes string to array.
IFS=',' read -ra volumes <<< "$volumes"

# source_directory=''
# backupdir=''
# b2bucketname=''
thismonth=`date --date="this month" +%Y%m01`
oldmonth=`date --date="3 months ago" +%Y%m01`

# Functions

b2_add_thismonth () {
  docker run --rm -v ~/.b2_account_info:/root/.b2_account_info -v $backupdir:/app b2 \
    b2 upload-file --noProgress $b2bucketname $thismonth-$volume.tar.gz.gpg $thismonth-$volume.tar.gz.gpg
}

b2_delete_oldmonth () {
  file_version=`docker run --rm -v ~/.b2_account_info:/root/.b2_account_info b2 \
    b2 ls --long $b2bucketname | grep "$oldmonth-$volume" | awk '{print $1}'`
  echo "Deleting ${file_version}."
  docker run --rm -v ~/.b2_account_info:/root/.b2_account_info b2 \
    b2 delete-file-version $file_version
}

# Main

echo
echo "Monthly archival backup."
echo "========================"
echo
echo "Starting time:"
date
echo

echo
echo "Create TAR file."
echo "================"
echo

for volume in ${volumes[*]}; do
  tar -C "$backupdir" -czf $backupdir/$thismonth-$volume.tar.gz "$volume"

  ls $backupdir/$thismonth-$volume.tar.gz
done

echo
echo "Encrypt TAR file."
echo "================="
echo

for volume in ${volumes[*]}; do
  gpg2 --batch \
    --cipher-algo AES256 \
    --symmetric \
    --passphrase-file ~/.secret \
    --output $backupdir/$thismonth-$volume.tar.gz.gpg \
    $backupdir/$thismonth-$volume.tar.gz

  ls $backupdir/$thismonth-$volume.tar.gz.gpg
done

# TODO.  Add sha1sum.  The b2 CLI does not currently support/respect the `--sha1` parameter, but
# according to [Github Issue Link], it will soon.

echo
echo "Upload current month (${thismonth}) to b2:"
echo "======================================"
echo

for volume in ${volumes[*]}; do
  b2_add_thismonth
done

# TODO.  Add logic to verify that upload succeeded before continuing on to delete old backups.

echo
echo "Delete old month (${oldmonth}) from b2:"
echo "===================================="
echo

for volume in ${volumes[*]}; do
  b2_delete_oldmonth
done

echo
echo "Delete old month (${oldmonth}) locally:"
echo "===================================="
echo

# rm -fv $backupdir/$oldmonth-$volume.tar.*

echo
echo "Backup complete."
echo "================"
echo
echo "Ending time:"
date
echo
