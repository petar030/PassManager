import json
import bcrypt
import os
from cryptography.fernet import Fernet

def make_file(file_name, password):
    new_file_name = file_name + ".pass"
    if os.path.isfile(new_file_name):
        print(f"File '{new_file_name}' already exists.")
        return None
    #TODO: check_password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()

    metadata = {"version": "1.0", "type": "pass", "salt": salt_hex, "hash": hashed_password_hex, "enc": "0"}
    data = {"metadata": metadata, "entries": []}
    try:
        with open(new_file_name, "w") as pass_file:
            pass_file.seek(0)
            json.dump(data, pass_file, indent=4)
        return new_file_name
    except Exception as e:
        print(f"Error creating file: {e}")
        return None
def check_file_type(file_name):
    if not file_name.endswith(".pass"):
        print(f"File '{file_name}' is not a .pass file.")
        return False

    if not os.path.isfile(file_name):
        print(f"File '{file_name}' does not exist.")
        return False

    if not os.access(file_name, os.R_OK):
        print(f"No read permission for file '{file_name}'.")
        return False

    try:
        with open(file_name, "r") as pass_file:
            data = json.load(pass_file)
            if "metadata" in data and "type" in data["metadata"] and data["metadata"]["type"] == "pass" and "salt" in data["metadata"] and "hash" in data["metadata"] and "enc" in data["metadata"]:
                return True
            else:
                print(f"File '{file_name}' is not a valid .pass file.")
                return False
    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def add_entry(file_name, name, user, password):
    if not check_file_type(file_name):
         return False
    if name == None or name == "":
        return False
    try:
         with open(file_name, "r") as pass_file:
             data = json.load(pass_file)
             if "entries" not in data:
                 return False
             for entry in data["entries"]:
                 if entry["name"] == name:
                     print(f"Entry with name '{name}' already exists.")
                     return False
             new_entry = {"name": name, "user": user, "password": password}
             data["entries"].append(new_entry)

         with open(file_name, "w") as pass_file:
             pass_file.seek(0)
             json.dump(data, pass_file, indent=4)
         return True

    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def edit_entry(file_name, name, user, password):
    if not check_file_type(file_name):
        return False
    try:
        with open(file_name, "r") as pass_file:
            data = json.load(pass_file)
            if "entries" not in data:
                return False
            edited = False
            for entry in data["entries"]:
                if entry["name"] == name:
                    entry["user"] = user
                    entry["password"] = password
                    edited = True
                    break
            if not edited:
                return False

        with open(file_name, "w") as pass_file:
            pass_file.seek(0)
            json.dump(data, pass_file, indent=4)
        return True

    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def remove_entry(file_name, name):
    if not check_file_type(file_name):
        return False
    try:
        with open(file_name, "r") as pass_file:
            data = json.load(pass_file)
            if "entries" not in data:
                return False
            check = False
            for entry in data["entries"]:
                if entry["name"] == name:
                    data["entries"].remove(entry)
                    check = True
                    break
            if not check:
                print(f"Entry with name '{name}' does not exist.")
                return False
            with open(file_name, "w") as pass_file:
                pass_file.seek(0)
                json.dump(data, pass_file, indent=4)
                return True
    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def list_entries(file_name):
    if not check_file_type(file_name):
        return False
    try:
        with open(file_name, "r") as pass_file:
            data = json.load(pass_file)
            if "entries" not in data:
                return False
            i = 1
            print("\n")
            for entry in data["entries"]:
                print(f"{i}. Name: {entry['name']}, User: {entry['user']}, Password: {entry['password']}")
                i += 1
            if i == 1:
                print("No entries found.")
            print("\n")
            return True
    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def authenticate_core(file_name, password):
    try:
        with open(file_name, "r") as pass_file:
            data = json.load(pass_file)
            if "metadata" not in data or "salt" not in data["metadata"] or "hash" not in data["metadata"]:
                print("Invalid file metadata.")
                return False
            salt_hex = data["metadata"]["salt"]
            hashed_password_hex = data["metadata"]["hash"]
            salt = bytes.fromhex(salt_hex)
            hashed_password = bytes.fromhex(hashed_password_hex)
            if bcrypt.hashpw(password.encode("utf-8"), salt) == hashed_password:
                return True
            else:
                print("Invalid password.")
                return False
    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def generate_key(password, salt):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from base64 import urlsafe_b64encode
    from hashlib import sha256

    # Derive a key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(salt),
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return urlsafe_b64encode(key)
def encrypt(file_name, password):
    with open(file_name, 'r') as file:
        data = json.load(file)
    if data['metadata']['enc'] == "1":
        return
    salt = data['metadata']['salt']
    key = generate_key(password, salt)
    fernet = Fernet(key)

    entries_json = json.dumps(data['entries']).encode()
    encrypted_entries = fernet.encrypt(entries_json)

    data['entries'] = encrypted_entries.decode()
    data['metadata']['enc'] = "1"

    with open(file_name, 'w') as file:
        json.dump(data, file, indent=4)
def decrypt(file_name, password):
    with open(file_name, 'r') as file:
        data = json.load(file)
    if data['metadata']['enc'] == "0":
        return
    salt = data['metadata']['salt']
    key = generate_key(password, salt)
    fernet = Fernet(key)

    encrypted_entries = data['entries'].encode()
    decrypted_entries = fernet.decrypt(encrypted_entries)

    data['entries'] = json.loads(decrypted_entries.decode())
    data['metadata']['enc'] = "0"

    with open(file_name, 'w') as file:
        json.dump(data, file, indent=4)