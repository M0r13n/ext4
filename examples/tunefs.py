import pprint

from ext4 import Ext4Filesystem, tunefs


def main():
    with Ext4Filesystem('ext4.img') as fs:
        pprint.pprint(tunefs(fs))

        if fs.checksum_valid:
            print(f"Superblock checksum is valid (0x{fs.sb.s_checksum:x}).")
        else:
            print("!!Corrupted superblock!!")
            print(f"Invalid checksum: 0x{fs.compute_checksum():x} != 0x{fs.sb.s_checksum:x}")


if __name__ == '__main__':
    main()
