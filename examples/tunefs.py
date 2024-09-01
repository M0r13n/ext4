import pprint

from ext4 import Ext4Filesystem, Inode, tunefs


def main():
    with Ext4Filesystem('ext4.img') as fs:
        pprint.pprint(tunefs(fs))


if __name__ == '__main__':
    main()
