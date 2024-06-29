#!/bin/bash

set -e

sudo umount /mnt/ext4
sudo losetup -d /dev/loop10
rm ext4.img
