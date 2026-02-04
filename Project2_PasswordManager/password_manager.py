import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"

def generate_key(master_password):
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(master_password.encode())
    )
    return Fernet(key)

def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}

    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except Exception:
        print("❌ Invalid master password or corrupted vault.")
        exit()

def save_vault(vault, fernet):
    encrypted_data = fernet.encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)

def add_entry(vault):
    site = input("Website/App: ")
    username = input("Username: ")
    password = getpass("Password: ")

    vault[site] = {
        "username": username,
        "password": password
    }
    print("✅ Entry added.")

def retrieve_entry(vault):
    site = input("Search site: ")
    entry = vault.get(site)

    if entry:
        print(f"\n🔐 {site}")
        print(f"Username: {entry['username']}")
        print(f"Password: {entry['password']}")
    else:
        print("❌ Entry not found.")

def delete_entry(vault):
    site = input("Delete site: ")
    if site in vault:
        del vault[site]
        print("🗑 Entry deleted.")
    else:
        print("❌ Entry not found.")

def search_entries(vault):
    keyword = input("Search keyword: ")
    results = [k for k in vault if keyword.lower() in k.lower()]

    if results:
        print("\n🔍 Matches:")
        for site in results:
            print("-", site)
    else:
        print("❌ No matches found.")

def main():
    master_password = getpass("Enter master password: ")
    fernet = generate_key(master_password)
    vault = load_vault(fernet)

    while True:
        print("\n--- Password Manager ---")
        print("1. Add password")
        print("2. Retrieve password")
        print("3. Delete password")
        print("4. Search")
        print("5. Exit")

        choice = input("Select option: ")

        if choice == "1":
            add_entry(vault)
        elif choice == "2":
            retrieve_entry(vault)
        elif choice == "3":
            delete_entry(vault)
        elif choice == "4":
            search_entries(vault)
        elif choice == "5":
            save_vault(vault, fernet)
            print("🔒 Vault locked. Goodbye.")
            break
        else:
            print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
