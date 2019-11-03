#!/bin/bash

# TODO: Break this out into a config file.
volumes=(volume1 volume2)

echo "Backing up NAS volumes."
echo
echo "Starting time:"
date
echo

for volume in ${volumes[*]}; do
  if [ -f /nas/$volume/SEMAPHORE.txt ]; then
    echo "Backing up $volume on NAS to backup server."
    echo "========================================"
    echo
    rsync -avh --delete /nas/$volume/ /backups/$volume/
    echo
  else
    echo "SEMAPHORE.txt missing.  Is NAS volume $volume mounted?"
    echo
  fi
done

echo "Ending time:"
date
