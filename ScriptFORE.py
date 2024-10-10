import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import binascii
import tkinter.messagebox as messagebox


FILE_SYSTEMS = {
    "01": "FAT12",
    "04": "FAT16",
    "06": "FAT16B",
    "07": "NTFS, HPFS, exFAT",
    "0B": "FAT32 CHS",
    "0C": "FAT32 LBA",
    "0E": "FAT16 LBA",
    "83": "Linux Native File System (ext2/3/4, JFS, Reiser, xiafs, and others)",

    }

def browse_image():
    filepath = filedialog.askopenfilename()
    if filepath:
        entry_image.delete(0, tk.END)
        entry_image.insert(0, filepath)

def read_mbr(image_path):
    SECTOR_SIZE = 512
    with open(image_path, 'rb') as f:
        mbr_data = f.read(512)
    
        mbr_hex = binascii.hexlify(mbr_data).decode('utf-8')
        
        # Display hexadecimal in the Text widget
        hex_display.delete('1.0', tk.END)
        hex_display.insert(tk.END, mbr_hex)

        treeview.delete(*treeview.get_children())  # Clear existing data
        
        # Loop over every partition
        for partition_number in range(0, 4):
            bootable_status = MBRAnalyse.bootable(mbr_hex, partition_number)
            starting_sector = MBRAnalyse.startingSector_CHS(mbr_hex, partition_number)
            ending_sector = MBRAnalyse.endingSector_CHS(mbr_hex, partition_number)
            starting_sector_lba = MBRAnalyse.startingSector_LBA(mbr_hex, partition_number)
            total_sectors_value = MBRAnalyse.totalSectors(mbr_hex, partition_number)
            partition_size = MBRAnalyse.calculate_partition_size(total_sectors_value)
            file_sys = MBRAnalyse.fileSys(mbr_hex, partition_number)
            
            
            # If it's the first partition, read and display the boot sector
            if partition_number == 0:
                boot_sector_offset = starting_sector_lba * SECTOR_SIZE
                f.seek(boot_sector_offset)
                boot_sector_data = f.read(SECTOR_SIZE)
                boot_sector_hex = binascii.hexlify(boot_sector_data).decode('utf-8')

                show_boot_sector(boot_sector_hex)
                
                jump_code = AnalyseBootSector.jumpCode(boot_sector_hex)
                oem = AnalyseBootSector.oem(boot_sector_hex)
                bytes_per_sector = AnalyseBootSector.bytesPerSector(boot_sector_hex)
                sectors_Per_Cluster=AnalyseBootSector.sectorsPerCluster(boot_sector_hex)
                reserved_Area = AnalyseBootSector.reservedArea(boot_sector_hex)
                numOf_FAT = AnalyseBootSector.numOfFAT(boot_sector_hex)
                numOfRootDir_Entries = AnalyseBootSector.numOfRootDirEntries(boot_sector_hex)
                numOf_Sectors = AnalyseBootSector.numOfSectors(boot_sector_hex)
                media_Type = AnalyseBootSector.mediaType(boot_sector_hex)
                FAT_Size = AnalyseBootSector.FATSize(boot_sector_hex)
                numOfSectorsPer_Track=AnalyseBootSector.numOfSectorsPerTrack(boot_sector_hex)
                numOf_Heads = AnalyseBootSector.numOfHeads(boot_sector_hex)
                numOfHidden_Sectors=AnalyseBootSector.numOfHiddenSectors(boot_sector_hex)
                flagss = AnalyseBootSector.Flags(boot_sector_hex)
                FAT_32_version=AnalyseBootSector.FAT32_version(boot_sector_hex)
                RootDirCluster_Number = AnalyseBootSector.RootDirClusterNumber(boot_sector_hex)
                FSINFOSector_Number =AnalyseBootSector.FSINFOSectorNumber(boot_sector_hex)
                BackupBoot_Sector = AnalyseBootSector.BackupBootSector(boot_sector_hex)
                IOSDrive_Number = AnalyseBootSector.BIOSDriveNumber(boot_sector_hex)
                extendedBoot_Signature =AnalyseBootSector.extendedBootSignature(boot_sector_hex)
                partitionSerial_Number =AnalyseBootSector.partitionSerialNumber(boot_sector_hex)
                volume_Name = AnalyseBootSector.volumeName(boot_sector_hex)
                BootRecordSignature = AnalyseBootSector.BootRecordSignature_1(boot_sector_hex)
                FileSystem_Type =AnalyseBootSector.FileSystemType(boot_sector_hex)
                Bootstrap_Code = AnalyseBootSector.BootstrapCode(boot_sector_hex)
                mediaDescriptor_Type =AnalyseBootSector.mediaDescriptorType(boot_sector_hex)
                size_total = bytes_per_sector * sectors_Per_Cluster
                

                if "FAT32" in file_sys:
                    show_boot_sector_info(jump_code, oem, bytes_per_sector,sectors_Per_Cluster,reserved_Area,numOf_FAT,numOfRootDir_Entries,numOf_Sectors,media_Type,
                        FAT_Size,numOfSectorsPer_Track,numOf_Heads,numOfHidden_Sectors,flagss,FAT_32_version,RootDirCluster_Number,FSINFOSector_Number,BackupBoot_Sector
                        ,IOSDrive_Number,extendedBoot_Signature,partitionSerial_Number,volume_Name,BootRecordSignature,FileSystem_Type,mediaDescriptor_Type,size_total)
                    show_bootsrap_code(Bootstrap_Code)                   
                else : 
                    messagebox.showerror("Error", "your file system is not FAT32 , klock OK for Analysis of MBR")

            treeview.insert("", "end", values=(partition_number + 1, bootable_status, "0x"+starting_sector[0:2], "0x"+ending_sector[0:2],
                "0x"+starting_sector[2:4], "0x"+ending_sector[2:4], "0x"+starting_sector[4:6], "0x"+ending_sector[4:6],
                starting_sector_lba, total_sectors_value, partition_size, file_sys,'''"0x"+mbr_signature'''))

def analyze_mbr():
    image_path = entry_image.get()
    if image_path:
        read_mbr(image_path)
    else:
        messagebox.showerror("Error", "Please select an image file.")


#-------------------------
def show_boot_sector(boot_sector_hex):
    # Créer une nouvelle fenêtre pour afficher le secteur d'amorçage
    boot_sector_window = tk.Toplevel()
    boot_sector_window.title("Boot Sector of First Partition")

    # Afficher les données hexadécimales dans un widget Text
    boot_sector_text = tk.Text(boot_sector_window, width=80, height=20)
    boot_sector_text.insert(tk.END, boot_sector_hex)
    boot_sector_text.pack(padx=10, pady=10)

#-------------Parsing  BOOT SECTOR of partition 1 -------------------

class AnalyseBootSector:
    BOOT_SECTOR_START = 0
    JUMP_CODE_SIZE = 3
    OEM_SIZE = 8
    BYTES_PER_SECTOR_OFFSET = 11
    BYTES_PER_SECTOR_SIZE = 2
    SECTORS_PER_CLUSTER_OFFSET = 13
    SECTORS_PER_CLUSTER_SIZE = 1
    RESERVED_AREA_OFFSET = 14
    RESERVED_AREA_SIZE = 2
    NUM_OF_FAT_OFFSET = 16
    NUM_OF_FAT_SIZE = 1
    NUM_OF_ROOT_DIR_ENTRIES_OFFSET = 17
    NUM_OF_ROOT_DIR_ENTRIES_SIZE = 2
    NUM_OF_SECTORS_OFFSET = 19
    NUM_OF_SECTORS_SIZE = 2
    MEDIA_TYPE_OFFSET = 21
    MEDIA_TYPE_SIZE = 1
    FAT_SIZE_OFFSET = 22
    FAT_SIZE_SIZE = 2
    NUM_OF_SECTORS_PER_TRACK_OFFSET = 24
    NUM_OF_SECTORS_PER_TRACK_SIZE = 2
    NUM_OF_HEADS_OFFSET = 26
    NUM_OF_HEADS_SIZE = 2
    NUM_OF_HIDDEN_SECTORS_OFFSET = 28
    NUM_OF_HIDDEN_SECTORS_SIZE = 4
    NUM_OF_SECTORS_PER_FAT_OFFSET = 36
    NUM_OF_SECTORS_PER_FAT_SIZE = 4
    FLAGS_OFFSET = 40
    FLAGS_SIZE = 2
    FAT32_VERSION_OFFSET = 42
    FAT32_VERSION_SIZE = 2
    ROOT_DIR_CLUSTER_NUMBER_OFFSET = 44
    ROOT_DIR_CLUSTER_NUMBER_SIZE = 4
    FSINFO_SECTOR_NUMBER_OFFSET = 48
    FSINFO_SECTOR_NUMBER_SIZE = 2
    BACKUP_BOOT_SECTOR_OFFSET = 50
    BACKUP_BOOT_SECTOR_SIZE = 2
    BIOS_DRIVE_NUMBER_OFFSET = 64
    BIOS_DRIVE_NUMBER_SIZE = 1
    EXTENDED_BOOT_SIGNATURE_OFFSET = 66
    EXTENDED_BOOT_SIGNATURE_SIZE = 1
    PARTITION_SERIAL_NUMBER_OFFSET = 67
    PARTITION_SERIAL_NUMBER_SIZE = 4
    VOLUME_NAME_OFFSET = 71
    VOLUME_NAME_SIZE = 11


    
    def jumpCode(hex_image):
        # Size: 3 Bytes
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START:AnalyseBootSector.BOOT_SECTOR_START + AnalyseBootSector.JUMP_CODE_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value  # Hexadecimal value in little endian format.

    
    def oem(hex_image):
        # Size: 8 Bytes
        jumpCode = AnalyseBootSector.JUMP_CODE_SIZE * 2
        hex_bytes = bytes.fromhex(hex_image[AnalyseBootSector.BOOT_SECTOR_START + jumpCode:AnalyseBootSector.BOOT_SECTOR_START + jumpCode + AnalyseBootSector.OEM_SIZE * 2])
        return hex_bytes.decode('ascii')


    def bytesPerSector(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.BYTES_PER_SECTOR_OFFSET * 2         # JumpCode + OEM
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.BYTES_PER_SECTOR_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)  # Convert hexadecimal to integer

    def sectorsPerCluster(hex_image):
        # Size: 1 byte
        start = AnalyseBootSector.SECTORS_PER_CLUSTER_OFFSET * 2  # JumpCode + OEM + BytesPerSector
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.SECTORS_PER_CLUSTER_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)  # Convert hexadecimal to integer

       
    def reservedArea(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.RESERVED_AREA_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.RESERVED_AREA_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    
    def numOfFAT(hex_image):
        # Size: 1 byte
        start = AnalyseBootSector.NUM_OF_FAT_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.NUM_OF_FAT_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)  # Convert hexadecimal to integer

    
    def numOfRootDirEntries(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.NUM_OF_ROOT_DIR_ENTRIES_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.NUM_OF_ROOT_DIR_ENTRIES_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)  # Convert hexadecimal to integer

    def numOfSectors(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.NUM_OF_SECTORS_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.NUM_OF_SECTORS_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def mediaType(hex_image):
        # Size: 1 byte
        start = AnalyseBootSector.MEDIA_TYPE_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors
        value = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.MEDIA_TYPE_SIZE * 2]
        return value

    
    def FATSize(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.FAT_SIZE_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.FAT_SIZE_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)  # Convert hexadecimal to integer

    def numOfSectorsPerTrack(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.NUM_OF_SECTORS_PER_TRACK_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FATSize
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.NUM_OF_SECTORS_PER_TRACK_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)  # Convert hexadecimal to integer

    def numOfHeads(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.NUM_OF_HEADS_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FATSize + NumberOfSectorsPerTrack
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.NUM_OF_HEADS_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def numOfHiddenSectors(hex_image):
        # Size: 4 bytes
        start = AnalyseBootSector.NUM_OF_HIDDEN_SECTORS_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FATSize + NumberOfSectorsPerTrack + NumberOfHeads
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.NUM_OF_HIDDEN_SECTORS_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def Flags(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.FLAGS_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.FLAGS_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        hex_value = big_endian[::-1].hex()
        int_value = int(hex_value, 16)
        bits = format(int_value, '0{}b'.format(AnalyseBootSector.FLAGS_SIZE * 8))  # convert integer to binary string with leading zero
        pretty_bits = ' '.join(bits[i:i + 4] for i in range(0, len(bits), 4))
        return pretty_bits  # If bit 7 is 1, only one of the FAT structures is active and its index is described in bits 0–3. Otherwise, all FAT structures are mirrors of each other.

    def FAT32_version(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.FAT32_VERSION_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.FAT32_VERSION_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def RootDirClusterNumber(hex_image):
        # Size: 4 bytes
        start = AnalyseBootSector.ROOT_DIR_CLUSTER_NUMBER_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.ROOT_DIR_CLUSTER_NUMBER_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def FSINFOSectorNumber(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.FSINFO_SECTOR_NUMBER_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.FSINFO_SECTOR_NUMBER_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def BackupBootSector(hex_image):
        # Size: 2 bytes
        start = AnalyseBootSector.BACKUP_BOOT_SECTOR_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.BACKUP_BOOT_SECTOR_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def BIOSDriveNumber(hex_image):
        # Size: 1 byte
        start = AnalyseBootSector.BIOS_DRIVE_NUMBER_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber + BackupBootSector + 12
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.BIOS_DRIVE_NUMBER_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def extendedBootSignature(hex_image):
        # Size: 1 byte
        start = AnalyseBootSector.EXTENDED_BOOT_SIGNATURE_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber + BackupBootSector + 12 + BIOSDriveNumber + 1
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.EXTENDED_BOOT_SIGNATURE_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value

    def partitionSerialNumber(hex_image):
        # Size: 4 bytes
        start = AnalyseBootSector.PARTITION_SERIAL_NUMBER_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber + BackupBootSector + 12 + BIOSDriveNumber + 1 + ExtendedBootSignature
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.PARTITION_SERIAL_NUMBER_SIZE * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return int(value, 16)

    def volumeName(hex_image):
        # Size: 11 bytes
        start = AnalyseBootSector.VOLUME_NAME_OFFSET * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber + BackupBootSector + 12 + BIOSDriveNumber + 1 + ExtendedBootSignature + PartitionSerialNumber
        hex_bytes = bytes.fromhex(hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + AnalyseBootSector.VOLUME_NAME_SIZE * 2])
        return hex_bytes.decode('ascii')

    def FileSystemType(hex_image):
        # Taille : 8 octets
        start = 82 * 2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber + BackupBootSector + 12 + BIOSDriveNumber + 1 + ExtendedBootSignature + PartitionSerialNumber + VolumeNameOfPartition
        hex_bytes = bytes.fromhex(hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + 8 * 2])
        return hex_bytes.decode('ascii')

    def BootRecordSignature_1(hex_image):
        # Taille : 2 octets
        start = 510*2  # JumpCode + OEM + BytesPerSector + SectorsPerCluster + reservedArea + numberOfFATs + NumberOfRootDirectoryEntries + NumberOfSectors + MediaType + FatSize + NumberOfSectorsPerTrack + NumberOfHeads + NumberOfHiddenSectors + NumberOfSectorsInPartition + NumberOfSectorsPerFAT + Flags + FAT32Version + RootDirectoryClusterNumber + FSINFOSectorNumber + BackupBootSector + 12 + BIOSDriveNumber + 1 + ExtendedBootSignature + PartitionSerialNumber + VolumeNameOfPartition + FileSystemType + 420
        little_endian = hex_image[AnalyseBootSector.BOOT_SECTOR_START + start:AnalyseBootSector.BOOT_SECTOR_START + start + 2 * 2]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()
        return value

    MEDIA_TYPES = {
        0xF0: "1.4 MB floppy",
        0xF8: "Fixed disk"
    }
    def mediaDescriptorType(hex_image):
        media_byte = int(hex_image[21 * 2:22 * 2], 16)
        return AnalyseBootSector.MEDIA_TYPES.get(media_byte, "Unknown")

    def BootstrapCode(hex_image):
        start = 36  # Début du secteur de démarrage pour FAT32
        end = 510   # Fin du secteur de démarrage pour FAT32
        bootstrap_code = hex_image[start:end]
    # Formater la chaîne hexadécimale pour afficher les octets avec des espaces tous les deux caractères
        formatted_code = ' '.join(bootstrap_code[i:i+2] for i in range(0, len(bootstrap_code), 2))
    # Insérer un retour à la ligne après chaque groupe de 50 caractères
        formatted_code = '\n'.join(formatted_code[i:i+200] for i in range(0, len(formatted_code), 100))
        return formatted_code



def show_bootsrap_code(Bootstrap_Code):
    show_bootsrap_code = tk.Toplevel()
    show_bootsrap_code.title("boot stap code")

    label_sectors_per_cluster = tk.Label(show_bootsrap_code, text=" bootsrap code FAT32 : {}".format(Bootstrap_Code))
    label_sectors_per_cluster.pack()


def show_boot_sector_info(jump_code, oem, bytes_per_sector, sectors_per_cluster,reserved_Area,numOf_FAT,numOfRootDir_Entries,numOf_Sectors ,media_Type,FAT_Size,numOfSectorsPer_Track,
    numOf_Heads,numOfHidden_Sectors , flagss,FAT_32_version,RootDirCluster_Number,FSINFOSector_Number,BackupBoot_Sector,BIOSDrive_Number,extendedBoot_Signature
    ,partitionSerial_Number,volume_Name,BootRecordSignature,FileSystem_Type,mediaDescriptor_Type,size_total):

    boot_sector_info_window = tk.Toplevel()
    boot_sector_info_window.title("Parsing Boot Sector of Partition 1")

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="The size of each Cluster in Bytes : {}".format(size_total))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="media type : {}".format(mediaDescriptor_Type))
    label_sectors_per_cluster.pack()


    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Filesystem Type Label : {}".format(FileSystem_Type))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="boot sector Signature : {}".format(BootRecordSignature))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Volume name of the Partition : {}".format(volume_Name))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Serial Number of the Partition : {}".format(partitionSerial_Number))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Extended Boot Signature : {}".format(extendedBoot_Signature))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="BIOS INT13h drive number : {}".format(BIOSDrive_Number))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Sector Number of Filesystem Information (FSINFO) : {}".format(FSINFOSector_Number))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Sector Number of Boot Sector Backup Copy : {}".format(BackupBoot_Sector))
    label_sectors_per_cluster.pack()

    label_jump_code = tk.Label(boot_sector_info_window, text="Jump Code : {}".format(jump_code))
    label_jump_code.pack()

    label_oem = tk.Label(boot_sector_info_window, text="OEM: {}".format(oem))
    label_oem.pack()

    label_bytes_per_sector = tk.Label(boot_sector_info_window, text="Bytes Per Sector : {}".format(bytes_per_sector))
    label_bytes_per_sector.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Sectors Per Cluster : {}".format(sectors_per_cluster))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of Reserved Sectors : {}".format(reserved_Area))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of FAT copies : {}".format(numOf_FAT))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of Root directory entries : {}".format(numOfRootDir_Entries))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Total number of sectors in the filesystem :  {}".format(numOf_Sectors))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Media Descriptor Type :  {}".format(media_Type))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of sectors Per FAT:  {}".format(FAT_Size))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of sectors Per Track :  {}".format(numOfSectorsPer_Track))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of heads : {}".format(numOf_Heads))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="Number of headian sector :  {}".format(numOfHidden_Sectors))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="flagss :  {}".format(flagss))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="fat version  :  {}".format(FAT_32_version))
    label_sectors_per_cluster.pack()

    label_sectors_per_cluster = tk.Label(boot_sector_info_window, text="First cluster of root directory :  {}".format(RootDirCluster_Number))
    label_sectors_per_cluster.pack()


#------------------------------------------ ANALYSE MBR ----------------------------

class MBRAnalyse:
    SECTOR_SIZE = 512
    MASTER_BOOT_CODE_LENGTH = 446
    PARTITION_TABLES_LENGTH = 16
    BOOT_SIGNATURE_LENGTH = 2
    BOOT_SECTOR_START = 0
    FSINFO_SECTOR_START = 0
    BOOT_SECTOR_SIZE = 512
    MASTER_BOOT_CODE_LENGTH = 446
    PARTITION_TABLES_LENGTH = 16

    def bootable(mbr_hex, partition_number):
        offset = MBRAnalyse.MASTER_BOOT_CODE_LENGTH + MBRAnalyse.PARTITION_TABLES_LENGTH * partition_number
        if mbr_hex[offset*2:offset*2+2] == "80":
            return "Bootable"
        elif mbr_hex[offset*2:offset*2+2] == "00":
            return "NOT Bootable"
        else:
            return "NOT Defined"

    def startingSector_CHS(mbr_hex, partition_number):
        offset = MBRAnalyse.MASTER_BOOT_CODE_LENGTH + MBRAnalyse.PARTITION_TABLES_LENGTH * partition_number
        return mbr_hex[offset*2+2:offset*2+8]

    
    def endingSector_CHS(mbr_hex, partition_number):
        offset = MBRAnalyse.MASTER_BOOT_CODE_LENGTH + MBRAnalyse.PARTITION_TABLES_LENGTH * partition_number
        return mbr_hex[offset*2+10:offset*2+16]

    def startingSector_LBA(mbr_hex, partition_number):
        offset = MBRAnalyse.MASTER_BOOT_CODE_LENGTH + MBRAnalyse.PARTITION_TABLES_LENGTH * partition_number
        hex_value = mbr_hex[offset*2+16:offset*2+24]

        start_sector = bytes.fromhex(hex_value)
        start_sector = start_sector[::-1].hex().lstrip('0')

        if not start_sector:
            start_sector = '0'

        return int(start_sector, 16)

    
    def totalSectors(hex_image, partition_counter):
        hex_value = hex_image[MBRAnalyse.MASTER_BOOT_CODE_LENGTH*2+MBRAnalyse.PARTITION_TABLES_LENGTH*2*partition_counter+24:MBRAnalyse.MASTER_BOOT_CODE_LENGTH*2+MBRAnalyse.PARTITION_TABLES_LENGTH*2*partition_counter+32]

        total_sectors = bytes.fromhex(hex_value)
        total_sectors = total_sectors[::-1].hex().lstrip('0')
        if total_sectors:
            decimal = int(total_sectors, 16)
        if not total_sectors:
            decimal = '0'

        return decimal

    
    def fileSys(hex_image, partition_number):
        for key in FILE_SYSTEMS:
            offset = MBRAnalyse.MASTER_BOOT_CODE_LENGTH + MBRAnalyse.PARTITION_TABLES_LENGTH * partition_number
            if str(hex_image[offset*2+8:offset*2+10]).lower() == str(key).lower():
                return FILE_SYSTEMS[key]
        return "Unknown (0x" + str(hex_image[offset*2+8:offset*2+10]) + ")"

    
    def calculate_partition_size(total_sectors_value):
        sector_size = 512  # Assuming sector size is 512 bytes
        partition_size_bytes = total_sectors_value * sector_size
        return partition_size_bytes

    def MBRSignature(hex_image):
        little_endian = hex_image[-4:]
        big_endian = bytes.fromhex(little_endian)
        value = big_endian[::-1].hex()

        return value


root = tk.Tk()
root.title("MBR Analysis")

frame_superblock = tk.Frame(root)
frame_superblock.pack(pady=10)


frame_path = tk.Frame(root)
    
frame_path.pack(pady=10)

label_image = tk.Label(frame_path, text="Image Path:")
label_image.grid(row=0, column=0)

entry_image = tk.Entry(frame_path, width=40)
entry_image.grid(row=0, column=1)

button_browse = tk.Button(frame_path, text="Browse", command=browse_image)
button_browse.grid(row=0, column=2, padx=5)

button_analyze = tk.Button(root, text="Analyze MBR", command=analyze_mbr)
button_analyze.pack(pady=5)

hex_display = tk.Text(root, width=80, height=15)
hex_display.pack(pady=10)


treeview = ttk.Treeview(root, columns=("Partition", "Bootable Status", "start head","end head", "start sector","end sector" ,
    "start cylinder","end cylinder",
    "starting sector \n of partition", "Total Sectors", "Partition Size", "File System"),show="headings" , height=4)
treeview.heading("Partition", text="Partition")
treeview.heading("Bootable Status", text="Bootable Status")
treeview.heading("start head", text="start head")
treeview.heading("end head", text="end head")
treeview.heading("start sector", text="start sector")
treeview.heading("end sector", text="end sector")
treeview.heading("start cylinder", text="start cylinder")
treeview.heading("end cylinder", text="end cylinder")
treeview.heading("starting sector \n of partition", text="starting sector \n of partition")
treeview.heading("Total Sectors", text="Total Sectors")
treeview.heading("Partition Size", text="Partition Size(Bytes)")
treeview.heading("File System", text="File System")
treeview.pack(pady=100)


for col in treeview["columns"]:
    treeview.column(col, width=105)
  
treeview.pack(pady=100)

root.mainloop()
