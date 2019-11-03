#!/bin/bash

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
