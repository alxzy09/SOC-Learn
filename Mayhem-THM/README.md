# Mayhem

> Dalam Mayhem, kita telah diberikan file PCAP. Tugas kita adalah menganalisisnya, menemukan rahasianya, dan mendekode lalu lintasnya.

---

## Analisis PCAP

Sekilas, kita memiliki **lalu ​​lintas HTTP**. Ini berasal dari **server web Python**. File `Install.ps1` dan `notepad.exe` dikirim melalui port **1337**.
![](/Mayhem-THM/assets/image.avif)

Setelah transfer `notepad.exe` selesai, kita menerima lalu lintas HTTP lebih lanjut. Kali ini hanya melalui **port 80**. Permintaan **POST** dikirim secara berkala, dan isi datanya tampaknya **terenkripsi**.

![](/Mayhem-THM/assets/image.png)

Perilaku ini kemungkinan besar disebabkan oleh `notepad.exe`. Kami mengekstrak **HTTP Objects** untuk menganalisisnya lebih lanjut.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FXk5Q4uNIGQG8oQrTNxin%252Fgrafik.png%3Falt%3Dmedia%26token%3Db11ad662-2aa2-40f9-af89-4c75e07dbbfd&width=768&dpr=2&quality=100&sign=25375768&sv=2)

## Riset

Mendekompilasi file executable menggunakan Ghidra tidak menghasilkan temuan baru. Namun, kita juga dapat mengirimkannya ke Virustotal untuk dianalisis.

[Virustotal](https://www.virustotal.com/gui/file/99784f28e4e95f044d97e402bbf58f369c7c37f49dc5bf48e6b2e706181db3b7)

Seperti yang diharapkan, ini ditandai sebagai berbahaya. Ini juga terkait dengan Havoc, sebuah kerangka kerja C2. Ini bisa jadi sebuah beacon. Beacon C2 Havoc adalah agen ringan yang berkomunikasi dengan server C2 Havoc, memungkinkan kendali jarak jauh atas sistem yang disusupi. Biasanya beroperasi secara diam-diam, mengirimkan laporan berkala dan menerima instruksi.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FP6gScyLvLCDVWXah23Fn%252Fgrafik.png%3Falt%3Dmedia%26token%3Dc5f86af9-864e-4e0d-a5d4-050b43f46ae1&width=768&dpr=2&quality=100&sign=b531c297&sv=2)

Havoc: https://github.com/HavocFramework/Havoc

Cara menganalisis lalu lintas dari beacon Havoc dijelaskan oleh Immersive Labs dalam sebuah postingan blog.

https://www.immersivelabs.com/resources/blog/havoc-c2-framework-a-defensive-operators-guide

Dari postingan blog tersebut kita dapat memperoleh informasi yang diperlukan tentang cara mengidentifikasi dan menguraikan lalu lintas tersebut.

Seperti yang diasumsikan, lalu lintas data dienkripsi. Havoc menggunakan AES dalam mode CTR untuk tujuan ini.

Materi kunci (kunci AES + IV) juga ditransmisikan. Karena kita memiliki lalu lintas HTTP di depan kita, kemungkinan kita memiliki akses ke materi kunci tersebut.

Selain itu, nilai byte ajaib dikirimkan untuk mengidentifikasi lalu lintas iblis.

> Setelah memeriksa repositori GitHub Havoc C2, kami mengidentifikasi definisi nilai ajaib 0xDEADBEEF , yang ditemukan dalam file Defines.h .

Kami mencari nilai heksadesimal 0xDEADBEEF dan benar-benar menemukannya.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FhXBiVm45tvwnup9hB6pq%252Fgrafik.png%3Falt%3Dmedia%26token%3Dcc6714c4-1f5f-4d5d-bd1a-53e1681e590e&width=768&dpr=3&quality=100&sign=45637ce8&sv=2)

Selain itu, kami juga menemukan ID agen, kunci AES, dan IV seperti yang dijelaskan dalam postingan blog.

```
length field: 00000113   
magic byte header: deadbeef
agent id: b7d8
aes key: 946cf2f65ac2...
iv key: 8cd00c3e4392...
```

Dengan menggunakan tshark, kita dapat mengekstrak semua permintaan POST bertipe media dan menguraikannya satu per satu menggunakan CyberChef.

```
tshark -r traffic.pcapng -Y 'http.request.method == "POST"' -T fields -e media.type 
```

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FPwY2ZPLaQt5Id59VlCMv%252Fgrafik.png%3Falt%3Dmedia%26token%3Dbd82523d-9d9c-4b2b-9279-4e9873735752&width=768&dpr=2&quality=100&sign=6ff0d29&sv=2)


Namun, kita harus menghapus informasi header terlebih dahulu, atau hanya mempertimbangkan datanya saja. (Ditandai dengan warna putih pada gambar di atas). Dan kita lihat bahwa kita dapat menguraikan lalu lintas tersebut:

```
Paket-paket berikutnya setelah paket awal memiliki header tanpa kunci AES dan IV. Header ini hanya sepanjang 40 byte (untuk diidentifikasi oleh COMMAND_NOJOB). Dengan menghapus header ini terlebih dahulu, data selanjutnya dapat didekripsi dengan kunci dan IV yang sama.
```

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FhvSvSoI7c2G8whNxZiMQ%252Fgrafik.png%3Falt%3Dmedia%26token%3Dca54783f-8752-4d57-9c51-a1f890c95dc9&width=768&dpr=2&quality=100&sign=a0c1c44c&sv=2)

Untungnya, Immersive Labs juga menyediakan skrip yang memungkinkan Anda menganalisis lalu lintas Havoc PCAP. Skrip ini mampu mengekstrak kunci AES dan IV, mengidentifikasi perintah, dan menyimpan permintaan dan respons yang telah didekripsi.

https://github.com/Immersive-Labs-Sec/HavocC2-Forensics/blob/main/PacketCapture/havoc-pcap-parser.py

Kami menjalankan skrip tanpa flag khusus apa pun dan melihat bahwa skrip tersebut mampu mengekstrak kunci AES, IV, dan beberapa perintah. Kami tidak melihat apa yang sebenarnya terjadi.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FKb7M77wSp60xcj5SP6lf%252Fgrafik.png%3Falt%3Dmedia%26token%3D0fd76162-828d-4d9e-ab2e-e7e12cd0f0d5&width=768&dpr=2&quality=100&sign=15c1a050&sv=2)

Kita dapat mengidentifikasi perintah-perintah berikut.

```
COMMAND_NOJOB
COMMAND_MEM_FILE
COMMAND_PROC
```

Kita melihat kode sumber dan mendapati bahwa isi respons dan permintaan disimpan dalam bentuk terenkripsi sebagai .binfile di jalur penyimpanan jika --saveflag tersebut digunakan. Sayangnya, datanya agak berantakan dan tidak berurutan secara kronologis. Namun demikian, cukup untuk menjawab semua pertanyaan.

```
python3 havoc-pcap-parser.py --pcap traffic.pcapng --save .
```
![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FD0WCHOZnmRyiNl46zFuS%252Fgrafik.png%3Falt%3Dmedia%26token%3D1ddafba3-5b97-433f-83eb-230498dcb675&width=768&dpr=2&quality=100&sign=afb727d6&sv=2)

Contoh konten:

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FpwIri5jq1cxUZVPCxBNP%252Fgrafik.png%3Falt%3Dmedia%26token%3De18d3dcc-7e17-4676-aa15-a062fdd1f878&width=768&dpr=2&quality=100&sign=33148d48&sv=2)

## Memodifikasi havoc-pcap-parser.py dan Mendekripsi Lalu Lintas

```
Diuji dengan paket dan versi tshark berikut:

pyshark 0.6

lxml 5.3.2

tshark 4.2.2 Mungkin ada masalah di mana versi pyshark/tshark yang berbeda mengurai pcap secara berbeda, sehingga menghasilkan pengkodean heksadesimal yang berbeda di packet.http.file_data/field file_data kosong yang tidak akan memungkinkan Anda untuk mendekripsi data karena pengecualian yang dilemparkan oleh tsharkbody_to_bytes.
```

Kami menyesuaikan skrip untuk mendekripsi bahkan jika ```--saveflag``` tidak diatur dan jika sesuatu dapat didekripsi, itu juga akan dicetak ke konsol:

```
    # If we have keys lets decode the payload
    aes_keys = sessions.get(request_header['agent_id'], None)

    if not aes_keys:
        print(f"[!] No AES Keys for Agent with ID {request_header['agent_id']}")
        return

    # If save_path is set, make sure the directory exists
    if save_path and not os.path.exists(save_path):
        print(f"[!] Save path {save_path} does not exist, creating")
        os.makedirs(save_path)

    # Decrypt the Request Body
    if request_payload:
        print("  [+] Decrypting Request Body")
        decrypted_request = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], request_payload)
    
        # Always print
        decoded = decrypted_request.decode('utf-8', errors='ignore').strip()
        print(f"\n\033[92m[Decrypted Request]\033[0m\n{decoded}\n\n")

        # Save only if save_path is set
        if save_path:
            save_file = f'{save_path}/{unique_id}-request-{request_header["agent_id"]}.bin'
            with open(save_file, 'wb') as output_file:
                output_file.write(decrypted_request)

    # Decrypt the Response Body
    if response_payload:
        print("  [+] Decrypting Response Body")
        
        decrypted_response = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], response_payload)
    
        # Always print
        decoded = decrypted_response.decode('utf-8', errors='ignore').strip()
        print(f"\n\033[94m[Decrypted Response - {command}]\033[0m\n{decoded}\n\n")

        # Save only if save_path is set
        if save_path:
            save_file = f'{save_path}/{unique_id}-response-{request_header["agent_id"]}.bin'
            with open(save_file, 'wb') as output_file:
                output_file.write(decrypted_response)
```

Berikut adalah versi skrip yang telah disesuaikan:

```
# Copyright (C) 2024 Kev Breen, Immersive Labs
# https://github.com/Immersive-Labs-Sec/HavocC2-Forensics
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import argparse
import struct
import binascii
from binascii import unhexlify

from uuid import uuid4


try:
    import pyshark
except ImportError:
    print("[-] Pyshark not installed, please install with 'pip install pyshark'")
    exit(0)

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    print("[-] PyCryptodome not installed, please install with 'pip install pycryptodome'")
    exit(0)



demon_constants = {
    1: "GET_JOB",
    10: 'COMMAND_NOJOB',
    11: 'SLEEP',
    12: 'COMMAND_PROC_LIST',
    15: 'COMMAND_FS',
    20: 'COMMAND_INLINEEXECUTE',
    21: 'COMMAND_JOB',
    22: 'COMMAND_INJECT_DLL',
    24: 'COMMAND_INJECT_SHELLCODE',
    26: 'COMMAND_SPAWNDLL',
    27: 'COMMAND_PROC_PPIDSPOOF',
    40: 'COMMAND_TOKEN',
    99: 'DEMON_INIT',
    100: 'COMMAND_CHECKIN',
    2100: 'COMMAND_NET',
    2500: 'COMMAND_CONFIG',
    2510: 'COMMAND_SCREENSHOT',
    2520: 'COMMAND_PIVOT',
    2530: 'COMMAND_TRANSFER',
    2540: 'COMMAND_SOCKET',
    2550: 'COMMAND_KERBEROS',
    2560: 'COMMAND_MEM_FILE', # Beacon Object File
    4112: 'COMMAND_PROC', # Shell Command
    4113: 'COMMMAND_PS_IMPORT',
    8193: 'COMMAND_ASSEMBLY_INLINE_EXECUTE',
    8195: 'COMMAND_ASSEMBLY_LIST_VERSIONS',
}


# Used to store the AES Keys for each session
sessions = {}


def tsharkbody_to_bytes(hex_string):
    """
    Converts a TShark hex formated string to a byte string.
    
    :param hex_string: The hex string from TShark.
    :return: The byte string.
    """
    # its concatonated strings
    hex_string = hex_string.replace(':', '')
    #unhex it
    hex_bytes = unhexlify(hex_string)
    return hex_bytes



def aes_decrypt_ctr(aes_key, aes_iv, encrypted_payload):
    """
    Decrypts an AES-encrypted payload in CTR mode.

    :param aes_key: The AES key as a byte string.
    :param aes_iv: The AES IV (Initialization Vector) for the counter, as a byte string.
    :param encrypted_payload: The encrypted payload as a byte string.
    :return: The decrypted plaintext as a byte string.
    """
    # Initialize the counter for CTR mode
    ctr = Counter.new(128, initial_value=int.from_bytes(aes_iv, byteorder='big'))

    # Create the cipher in CTR mode
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

    # Decrypt the payload
    decrypted_payload = cipher.decrypt(encrypted_payload)

    return decrypted_payload



def parse_header(header_bytes):
    """
    Parses a 20-byte header into an object.

    :param header_bytes: A 20-byte header.
    :return: A dictionary representing the parsed header.
    """
    if len(header_bytes) != 20:
        raise ValueError("Header must be exactly 20 bytes long")

    # Unpack the header
    payload_size, magic_bytes, agent_id, command_id, mem_id = struct.unpack('>I4s4sI4s', header_bytes)

    # Convert bytes to appropriate representations
    magic_bytes_str = binascii.hexlify(magic_bytes).decode('ascii')
    agent_id_str = binascii.hexlify(agent_id).decode('ascii')
    mem_id_str = binascii.hexlify(mem_id).decode('ascii')
    command_name = demon_constants.get(command_id, f'Unknown Command ID: {command_id}')

    return {
        'payload_size': payload_size,
        'magic_bytes': magic_bytes_str,
        'agent_id': agent_id_str,
        'command_id': command_name,
        'mem_id': mem_id_str
    }


def parse_request(http_pair, magic_bytes, save_path):
    request = http_pair['request']
    response = http_pair['response']#

    unique_id = uuid4()

    print("[+] Parsing Request")


    try:
        request_body = tsharkbody_to_bytes(request.get('file_data', ''))
        header_bytes = request_body[:20]
        request_payload = request_body[20:]
        request_header = parse_header(header_bytes)
    except Exception as e:
        print(f"[!] Error parsing request body: {e}")
        return


    # If there is no magic this is not Havoc
    if request_header.get("magic_bytes", '') != magic_bytes:
        return


    if request_header['command_id'] == 'DEMON_INIT':
        print("[+] Found Havoc C2")
        print(f"  [-] Agent ID: {request_header['agent_id']}")
        print(f"  [-] Magic Bytes: {request_header['magic_bytes']}")
        print(f"  [-] C2 Address: {request.get('uri')}")

        aes_key = request_body[20:52]
        aes_iv = request_body[52:68]

        print(f"  [+] Found AES Key")
        print(f"    [-] Key: {binascii.hexlify(aes_key).decode('ascii')}")
        print(f"    [-] IV: {binascii.hexlify(aes_iv).decode('ascii')}")

        if request_header['agent_id'] not in sessions:
            sessions[request_header['agent_id']] = {
                "aes_key": aes_key,
                "aes_iv": aes_iv
            }
        
        # We dont want to process the rest of the request
        response_payload = None

    elif request_header['command_id'] == 'GET_JOB':
        print("  [+] Job Request from Server to Agent")
         # if the pcap did not contain an init or we have manually passed keys add the found keys message
        
        # Grab the response header to get the incoming request. 

        try:
            response_body = tsharkbody_to_bytes(response.get('file_data', ''))

        except Exception as e:
            print(f"[!] Error parsing request body: {e}")
            return


        header_bytes = response_body[:12]
        response_payload = response_body[12:]
        command_id = struct.unpack('<H', header_bytes[:2])[0]

        command = demon_constants.get(command_id, f'Unknown Command ID: {command_id}')

        print(f"    [-] C2 Address: {request.get('uri')}")
        print(f"    [-] Comamnd: {command}")

    else:
        print(f"  [+] Unknown Command: {request_header['command_id']}")
        response_payload = None

    # If we have keys lets decode the payload
    aes_keys = sessions.get(request_header['agent_id'], None)

    if not aes_keys:
        print(f"[!] No AES Keys for Agent with ID {request_header['agent_id']}")
        return

    # If save_path is set, make sure the directory exists
    if save_path and not os.path.exists(save_path):
        print(f"[!] Save path {save_path} does not exist, creating")
        os.makedirs(save_path)

    # Decrypt the Request Body
    if request_payload:
        print("  [+] Decrypting Request Body")
        decrypted_request = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], request_payload)
    
        # Always print
        decoded = decrypted_request.decode('utf-8', errors='ignore').strip()
        print(f"\n\033[92m[Decrypted Request]\033[0m\n{decoded}\n\n")

        # Save only if save_path is set
        if save_path:
            save_file = f'{save_path}/{unique_id}-request-{request_header["agent_id"]}.bin'
            with open(save_file, 'wb') as output_file:
                output_file.write(decrypted_request)

    # Decrypt the Response Body
    if response_payload:
        print("  [+] Decrypting Response Body")
        
        decrypted_response = aes_decrypt_ctr(aes_keys['aes_key'], aes_keys['aes_iv'], response_payload)
    
        # Always print
        decoded = decrypted_response.decode('utf-8', errors='ignore').strip()
        print(f"\n\033[94m[Decrypted Response - {command}]\033[0m\n{decoded}\n\n")

        # Save only if save_path is set
        if save_path:
            save_file = f'{save_path}/{unique_id}-response-{request_header["agent_id"]}.bin'
            with open(save_file, 'wb') as output_file:
                output_file.write(decrypted_response)


def read_pcap_and_get_http_pairs(pcap_file, magic_bytes, save_path):
    capture = pyshark.FileCapture(pcap_file, display_filter='http')
    http_pairs = {}
    current_stream = None
    request_data = None

    print("[+] Parsing Packets")

    for packet in capture:
        try:
            # Check if we are still in the same TCP stream
            if current_stream != packet.tcp.stream:
                # Reset for a new stream
                current_stream = packet.tcp.stream
                request_data = None

            if 'HTTP' in packet:
                if hasattr(packet.http, 'request_method'):
                    # This is a request
                    request_data = {
                        'method': packet.http.request_method,
                        'uri': packet.http.request_full_uri,
                        'headers': packet.http.get_field_value('request_line'),
                        'file_data': packet.http.file_data if hasattr(packet.http, 'file_data') else None
                    }
                elif hasattr(packet.http, 'response_code') and request_data:
                    # This is a response paired with the previous request
                    response_data = {
                        'code': packet.http.response_code,
                        'phrase': packet.http.response_phrase,
                        'headers': packet.http.get_field_value('response_line'),
                        'file_data': packet.http.file_data if hasattr(packet.http, 'file_data') else None
                    }
                    # Pair them together in a dictionary
                    http_pairs[f"{current_stream}_{packet.http.request_in}"] = {
                        'request': request_data,
                        'response': response_data
                    }

                    parse_request(http_pairs[f"{current_stream}_{packet.http.request_in}"], magic_bytes, save_path)

                    #print(http_pairs[f"{current_stream}_{packet.http.request_in}"])

                    request_data = None  # Reset request data after pairing
        except AttributeError as e:
            # Ignore packets that don't have the necessary HTTP fields
            pass



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Havoc Traffic from a PCAP')

    parser.add_argument(
        '--pcap',
        help='Path to pcap file',
        required=True)
    

    parser.add_argument(
        "--aes-key", 
        help="AES key", 
        required=False)
    
    parser.add_argument(
        "--aes-iv", 
        help="AES initialization vector", 
        required=False)
    
    parser.add_argument(
        "--agent-id", 
        help="Agent ID", 
        required=False)

    parser.add_argument(
        '--save',
        help='Save decrypted payloads to file',
        default=False,
        required=False)

    parser.add_argument(
        '--magic',
        help='Set the magic bytes marker for the Havoc C2 traffic',
        default='deadbeef',
        required=False)


    # Parse the arguments
    args = parser.parse_args()

    # Custom check for the optional values
    if any([args.aes_key, args.aes_iv, args.agent_id]) and not all([args.aes_key, args.aes_iv, args.agent_id]):
        parser.error("[!] If you provide one of 'aes-key', 'aes-iv', or 'agent-id', you must provide all three.")
    
    if args.agent_id and args.aes_key and args.aes_iv:
        sessions[args.agent_id] = {
            "aes_key": unhexlify(args.aes_key),
            "aes_iv": unhexlify(args.aes_iv)
        }
        print(f"[+] Added session keys for Agent ID {args.agent_id}")

    #find_havoc_packets(packets, args.save)


    # Usage example
    http_pairs = read_pcap_and_get_http_pairs(args.pcap, args.magic, args.save)

```

Setelah menjalankan skrip, kita dapat menjawab pertanyaan tersebut dengan memberikan konteks pada perintah yang dikeluarkan:

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FGzJd5OTc34ncu1QF8AS6%252Fgrafik.png%3Falt%3Dmedia%26token%3D36511b20-2da6-4eb1-b426-99fda2a6f22a&width=768&dpr=2&quality=100&sign=547bae1f&sv=2)

## Berapakah SID pengguna yang digunakan penyerang untuk menjalankan semua serangan?

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252F7kDBIYRls8Fgsv8X7tTD%252Fgrafik.png%3Falt%3Dmedia%26token%3Dd31c6dd0-2ddc-4621-b52f-8d311891e145&width=768&dpr=2&quality=100&sign=7bb28740&sv=2)

## Berapakah Alamat IPv6 Link-local dari server tersebut? Masukkan jawaban persis seperti yang Anda lihat.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252F0e99ts7tJNWJ2l0KOql5%252Fgrafik.png%3Falt%3Dmedia%26token%3Da2a13a02-580a-40f2-9d60-5c061de33088&width=768&dpr=2&quality=100&sign=fa80442c&sv=2)

## Penyerang mencetak sebuah bendera agar kita bisa melihatnya. Bendera apakah itu?

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FsIvdbppB9xTckRhiOSqk%252Fgrafik.png%3Falt%3Dmedia%26token%3D4def98a1-6a8b-438e-88ef-0a047f37413f&width=768&dpr=2&quality=100&sign=e71c17b0&sv=2)

## Penyerang menambahkan akun baru sebagai mekanisme persistensi. Apa nama pengguna dan kata sandi akun tersebut? Formatnya adalah nama pengguna:kata sandi.

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252F6jSqUCK0fZyogKU1NIjj%252Fgrafik.png%3Falt%3Dmedia%26token%3D7849e07c-e776-41e5-90d7-ff269cdefaae&width=768&dpr=2&quality=100&sign=7f5db29&sv=2)

## Penyerang menemukan sebuah file penting di server. Apa jalur lengkap file tersebut?

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252F9AL7ObI62B5wHz5HYE4P%252Fgrafik.png%3Falt%3Dmedia%26token%3Dd9242a10-2cc6-42f9-bf95-f83ba78f87fb&width=768&dpr=2&quality=100&sign=41859468&sv=2)

## Apa flag yang ditemukan di dalam file dari pertanyaan 5?

![](https://0xb0b.gitbook.io/writeups/~gitbook/image?url=https%3A%2F%2F2148487935-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FoqaFccsCrwKo1CHmLRKW%252Fuploads%252FRZc77Muw7a1cIsvNnn28%252Fgrafik.png%3Falt%3Dmedia%26token%3D2fbaadf5-3a14-4d9b-9095-5cc96864a082&width=768&dpr=2&quality=100&sign=48943b8d&sv=2)