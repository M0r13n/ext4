#!/bin/bash

set -e

dd if=/dev/zero of=ext4.img bs=1M count=1000
sudo losetup /dev/loop10 ext4.img
sudo mkfs.ext4 /dev/loop10
sudo mkdir  /mnt/ext4
sudo mount /dev/loop10 /mnt/ext4
