# KnexyceBTC

def install_pip():
    import subprocess
    import sys
    import os
    import urllib.request
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'])
        print("PIP is already installed.")
        return
    except subprocess.CalledProcessError:
        print("PIP is not installed. Installing...")
    try:
        subprocess.check_call([sys.executable, '-m', 'ensurepip'])
        print("PIP has been installed successfully using 'ensurepip'.")
        return
    except subprocess.CalledProcessError:
        print("'ensurepip' has failed. Attempting to install PIP via 'get-pip.py'...")
    try:
        url = "https://bootstrap.pypa.io/get-pip.py"
        get_pip_script = "get-pip.py"
        urllib.request.urlretrieve(url, get_pip_script)
        print("Downloaded 'get-pip.py'.")
        subprocess.check_call([sys.executable, get_pip_script])
        print("PIP has been installed successfully using 'get-pip.py'.")
        os.remove(get_pip_script)
        print("Cleaned up 'get-pip.py'.")
    except Exception as e:
        print(f"Failed to install PIP: {e}")
        sys.exit(1)

def pip_install(package_name, upgrade=True, user=False):
    import subprocess
    import sys
    def install_package(package_name):
        try:
            command = [sys.executable, '-m', 'pip', 'install', package_name]
            if upgrade:
                command.append('--upgrade')
            if user:
                command.append('--user')
            subprocess.run(command, check=True)
            print(f"{package_name} has been installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {package_name}: {e}")
    install_package(package_name)

def upgrade_pip():
    import subprocess
    import sys
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        print("PIP has been upgraded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to upgrade PIP: {e}")

def clear_screen():
    import platform
    import subprocess
    method = ['cls'] if platform.system() == 'Windows' else ['clear']
    try:
        subprocess.run(method, check=True)
    except Exception as e:
        print(f"Error: {e}")
        try:
            subprocess.run(['tput', 'clear'], check=True)
        except Exception as e2:
            print(f"Error: {e2}")
            print("\033[H\033[J", end="")

def handle_dependencies():
    install_pip()
    upgrade_pip()
    pip_install("secp256k1")
    pip_install("base58")
    pip_install("bitcoinlib")
    pip_install("cryptography")
    pip_install("prompt_toolkit")
    pip_install("paho-mqtt")

print("Upgrade/update system and install needed dependencies?")
upgrade_ask = input("[y/n]: ")
if upgrade_ask.lower() == "y":
    handle_dependencies()

try:
    import hashlib
    import base64
    import base58
    from decimal import Decimal
    import secp256k1
    import os
    from secp256k1 import PrivateKey
    import re
    import paho.mqtt.client as mqtt
    import threading
    import sys
    from prompt_toolkit import PromptSession
    from prompt_toolkit.patch_stdout import patch_stdout
    import getpass
    from bitcoinlib.wallets import Wallet, wallet_delete
    from bitcoinlib.keys import HDKey
    from bitcoinlib.services.services import Service
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("Error: Missing dependencies.")

def encrypt_message(message: str, knexyce_key: str):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(knexyce_key.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    encrypted_data = salt + iv + encrypted_message
    encrypted_message_base64 = base64.b64encode(encrypted_data).decode()
    return encrypted_message_base64

def decrypt_message(encrypted_message_base64: str, knexyce_key: str):
    encrypted_data = base64.b64decode(encrypted_message_base64)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(knexyce_key.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()

def create_wallet():
    def generate_valid_private_key():
        while True:
            private_key_bytes = os.urandom(32)
            private_key_int = int.from_bytes(private_key_bytes, byteorder='big')
            if 1 <= private_key_int < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
                return private_key_bytes
            else:
                continue
    
    def public_key_to_address(public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        network_prefix = b'\x00'
        prefixed_hash = network_prefix + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
        address_bytes = prefixed_hash + checksum
        address = base58.b58encode(address_bytes)
        return address.decode('utf-8')
    
    storage_valid_private_key = generate_valid_private_key()
    storage_private_key = PrivateKey(storage_valid_private_key)
    storage_public_key = storage_private_key.pubkey
    transaction_valid_private_key = generate_valid_private_key()
    transaction_private_key = PrivateKey(transaction_valid_private_key)
    transaction_public_key = transaction_private_key.pubkey
    sto_pri = storage_private_key.private_key.hex()
    sto_pub = storage_public_key.serialize(compressed=True).hex()
    sto_add = public_key_to_address(storage_public_key.serialize(compressed=True))
    tra_pri = transaction_private_key.private_key.hex()
    tra_pub = transaction_public_key.serialize(compressed=True).hex()
    tra_add = public_key_to_address(transaction_public_key.serialize(compressed=True))
    passphrase = getpass.getpass("Enter a secure passphrase to encrypt the Private Keys. ")
    enc_sto_pri = encrypt_message(sto_pri, passphrase)
    enc_tra_pri = encrypt_message(tra_pri, passphrase)
    private_key_bytes = None
    storage_valid_private_key = None
    transaction_valid_private_key = None
    storage_private_key = None
    transaction_private_key = None
    sto_pri = None
    tra_pri = None
    print("")
    print("Bitcoin Wallet Info")
    print("To decrypt the Private Keys, enter the 'decrypt' command.")
    print("")
    print("Bitcoin Storage Wallet")
    print(f"Private Key (Encrypted): {enc_sto_pri}")
    print(f"Public Key: {sto_pub}")
    print(f"Bitcoin Address: {sto_add}")
    print("")
    print("Bitcoin Transaction Wallet")
    print(f"Private Key (Encrypted): {enc_tra_pri}")
    print(f"Public Key: {tra_pub}")
    print(f"Bitcoin Address: {tra_add}")
    print("")

def decrypt_keys(enc_sto_pri=None, enc_tra_pri=None):
    enc_sto_pri = input("Enter the Encrypted Storage Private Key. ").strip()
    enc_tra_pri = input("Enter the Encrypted Transaction Private Key. ").strip()
    passphrase = getpass.getpass("Enter the passphrase for the Encrypted Private Keys. ")
    dec_sto_pri = decrypt_message(enc_sto_pri, passphrase)
    dec_tra_pri = decrypt_message(enc_tra_pri, passphrase)
    print(f"Decrypted Storage Key: {dec_sto_pri}")
    print(f"Decrypted Transaction Key: {dec_tra_pri}")

def hex_to_wif(private_key_hex, compressed=True):
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key_with_version = b'\x80' + private_key_bytes
    if compressed:
        private_key_with_version += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(private_key_with_version).digest()).digest()[:4]
    wif = base58.b58encode(private_key_with_version + checksum)
    return wif.decode('utf-8')

def create_transaction():
    wallet_name = 'temp_wallet'
    try:
        key_type = int(input("Do you have a WIF or Raw Private Key? (Enter '1' for WIF. Enter '2' for Raw.) "))
        if key_type == 2:
            private_key = getpass.getpass("Enter the Raw Bitcoin Private Key (Hex). ")
            key_compressed = input("Should the WIF Key be compressed? [y/n]: ")
            if key_compressed.lower() == "y":
                wif_private_key = hex_to_wif(private_key, compressed=True)
            elif key_compressed.lower() == "n":
                wif_private_key = hex_to_wif(private_key, compressed=False)
        elif key_type == 1:
            wif_private_key = getpass.getpass("Enter the WIF Bitcoin Private Key. ")
        else:
            print("Invalid input.")
            return
        to_address = input("Enter the Target Bitcoin Address. ")
        tx_amount = float(input("Enter the amount of BTC to send. "))
        fee_satoshis = float(input("Enter the amount of Satoshis you would like to use as the fee. "))
        try:
            wallet_delete(wallet_name)
        except:
            pass
        key = HDKey(import_key=wif_private_key, network='bitcoin')
        wallet = Wallet.create(wallet_name, keys=key, network='bitcoin', witness_type='segwit')
        wallet.utxos_update()
        print(f"Creating transaction for {to_address} with {tx_amount} BTC...")
        tx = wallet.send_to(to_address, tx_amount, fee=fee_satoshis)
        print("Transaction attempt created and broadcasted. Success is likely if no error message appears.")
        print(f"TXID: {tx.txid}")
    except Exception as e:
        print(f"Transaction failed: {e}")
    finally:
        try:
            wallet_delete(wallet_name)
        except:
            pass

def check_balance():
    address = input("Enter a Bitcoin Address to check its balance. ").strip()
    srv = Service()
    result = srv.getbalance(address)
    satoshis = result
    btc_balance = satoshis / 1e8
    print("Balance (BTC):", btc_balance)

def kmsg():
    def get_message(client, userdata, msg):
        message = msg.payload.decode()
        if message.startswith("[enc]"):
            try:
                decrypted_message = decrypt_message(message[5:], knexyce_key)
            except Exception as e:
                decrypted_message = "[Decryption failed.]"
        else:
            decrypted_message = message
        if not decrypted_message.startswith(screen_name):
            print(decrypted_message)
    
    def send_messages(client):
        session = PromptSession("> " + screen_name)
        with patch_stdout():
            while not stop_event.is_set():
                try:
                    user_input = session.prompt()
                    text = user_input.strip()
                    if text == "":
                        continue
                    if text == "/exit":
                        stop_event.set()
                        client.disconnect()
                        client.loop_stop()
                        print("Exited.")
                        break
                    if text == "/clear":
                        clear_screen()
                        continue
                    full_msg = f"{screen_name}{text}"
                    encrypted_msg = encrypt_message(full_msg, knexyce_key)
                    client.publish(TOPIC, "[enc]" + encrypted_msg)
                except KeyboardInterrupt:
                    continue
                except EOFError:
                    stop_event.set()
                    client.disconnect()
                    client.loop_stop()
                    print("Exited.")
                    break
                except Exception as e:
                    print(f"Error: {e}")
    stop_event = threading.Event()
    BROKER = input("Enter the MQTT Broker's domain/address. ")
    PORT = int(input("Enter the port of communications. "))
    TOPIC = input("Enter the name chat session's name. ")
    knexyce_key = getpass.getpass("Enter the shared chat decryption key. ")
    screen_name = f"{name}@Knexyce: [KMSG] "
    print("")
    print("KnexyceMSG")
    print("")
    print("Enter '/clear' to clear.")
    print("Enter '/exit' to exit.")
    print("")
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, protocol=mqtt.MQTTv311)
    client.on_message = get_message
    client.connect(BROKER, PORT, 60)
    client.subscribe(TOPIC)
    client.loop_start()
    sender_thread = threading.Thread(target=send_messages, args=(client,))
    sender_thread.start()
    sender_thread.join()

def knexyce_command_line_help():
    print("Note: Do not include ' or ' in the command.")
    print("Commands: ")
    print("'help': Provides a list of commands.")
    print("'create': Creates a Knexyce Bitcoin Wallet.")
    print("'check': Checks how much Bitcoin is in a wallet.")
    print("'send': Makes a Bitcoin transaction.")
    print("'chat': Launches KnexyceMSG.")
    print("'clear': Clears the screen.")
    print("'exit': Exits KBTC.")

print("")
print("KnexyceBTC")
print("")
print("All rights regarding KBTC/KnexyceBTC are reserved by Knexyce.")
print("")
print("Enter 'help' without any quotations for a list of commands.")
print("")

name = input("Enter a username. ")
username = name + "@Knexyce: [KBTC] "

try:
    while True:
        knexyce_input = input(username)
        if knexyce_input.lower() == "help":
            knexyce_command_line_help()
        elif knexyce_input.lower() == "create":
            create_wallet()
        elif knexyce_input.lower() == "check":
            check_balance()
        elif knexyce_input.lower() == "send":
            create_transaction()
        elif knexyce_input.lower() == "chat":
            kmsg()
        elif knexyce_input.lower() == "decrypt":
            decrypt_keys()
        elif knexyce_input.lower() == "clear":
            clear_screen()
        elif knexyce_input.lower() == "exit":
            break
        else:
            print("Error: Invalid command.")
except Exception as e:
    print(f"Error: {e}")

# This software was created by Ayan Alam.
# Note: Knexyce is a brand/group name assigned to software, tools, or other resources made by Ayan Alam.
# All rights to this software are reserved by Knexyce.