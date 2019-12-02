#!/bin/bash

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

echo "Backing up NAS volumes."
echo
echo "Starting time:"
date
echo

for volume in ${volumes[*]}; do
  if [ -f $nasdir/$volume/SEMAPHORE.txt ]; then
    echo "Backing up $volume on NAS to backup server."
    echo "========================================"
    echo
    rsync -avh --delete $nasdir/$volume/ $backupdir/$volume/
    echo
  else
    echo "SEMAPHORE.txt missing.  Is NAS volume $volume mounted?"
    echo
  fi
done

echo "Ending time:"
date
