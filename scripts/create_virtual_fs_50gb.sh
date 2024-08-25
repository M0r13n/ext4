#!/bin/bash

set -e

IMG_FILE="ext4.img"
LOOP_DEVICE="/dev/loop1338"
MOUNT_POINT="/mnt/ext4"

# Create the image file if it does not exist
if [ ! -f $IMG_FILE ]; then
  dd if=/dev/zero of=$IMG_FILE bs=1M count=50000
fi

# Set up the loop device if it is not already set up
if ! losetup -j $IMG_FILE | grep -q $LOOP_DEVICE; then
  sudo losetup $LOOP_DEVICE $IMG_FILE
fi

# Create the filesystem if it does not already exist
if ! sudo file -s $LOOP_DEVICE | grep -q 'ext4 filesystem data'; then
  sudo mkfs.ext4 $LOOP_DEVICE
fi

# Create the mount point if it does not exist
if [ ! -d $MOUNT_POINT ]; then
  sudo mkdir -p $MOUNT_POINT
fi

# Mount the filesystem if it is not already mounted
if ! mountpoint -q $MOUNT_POINT; then
  sudo mount $LOOP_DEVICE $MOUNT_POINT
fi

# Permissions
sudo chown -R leon:leon /mnt/ext4/
