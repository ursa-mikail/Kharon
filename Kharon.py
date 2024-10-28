# Kharon.py
"""
1. Check if the secrets directory exists: If it doesn't, prompt for enrollment.
2. Show the menu first: If the directory exists, display the menu immediately.
3. Provide password attempts: Allow the user to attempt accessing the secrets with a password up to 5 times if they choose to do so.
"""
"""
to-do:
1. load secret, i.e. add secret json files to secrets directory
2. consider access different secrets*.json
3. add when the secrets is rotated, add the old secrets to secrets backed-up directory, and state the timestamp when it was rotated, i.e. `time_rotated`
"""
import os
import json
import secrets
import datetime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag
from getpass import getpass

DIR_START = './sample_data'
SECRETS_DIR = os.path.join(DIR_START, 'secrets')
BACKUP_DIR = os.path.join(DIR_START, 'secrets_backed_up')
SECRET_FILE = os.path.join(SECRETS_DIR, 'secrets.json')
UNCIPHERED_EXPORT_FILE = os.path.join(SECRETS_DIR, 'secrets_unencrypted.json')

# Ensure directories exist
os.makedirs(SECRETS_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

def derive_key(password, salt):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'secrets encryption',
        backend=default_backend()
    )
    return hkdf.derive(password.encode())

def encrypt_data(data, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return salt, iv, encryptor.tag, encrypted_data

def decrypt_data(salt, iv, tag, encrypted_data, password):
    key = derive_key(password, salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def load_secrets(password):
    if not os.path.exists(SECRET_FILE):
        return {}
    with open(SECRET_FILE, 'rb') as f:
        salt = f.read(16)
        iv = f.read(12)
        tag = f.read(16)
        encrypted_data = f.read()

    try:
        decrypted_data = decrypt_data(salt, iv, tag, encrypted_data, password)
        return json.loads(decrypted_data.decode())
    except InvalidSignature:
        print("Invalid password.")
        return None

def save_secrets(secrets_data, password):
    data = json.dumps(secrets_data)
    salt, iv, tag, encrypted_data = encrypt_data(data, password)
    with open(SECRET_FILE, 'wb') as f:
        f.write(salt + iv + tag + encrypted_data)

def create_secret(secrets_data, password):
    domain = input("Enter domain name for the secret: ")
    choice = input("Generate random secret? (Y/N): ").strip().lower()
    if choice == 'y':
        num_bytes = int(input("Enter the number of bytes for the random secret: "))
        secret = secrets.token_hex(num_bytes)
    else:
        secret = input("Enter your secret: ")

    start_time = datetime.datetime.now().isoformat()
    expiry_choice = input("Does this secret have an expiry? (Y/N): ").strip().lower()
    end_time = (datetime.datetime.now() + datetime.timedelta(days=int(input("Enter expiry duration in days: ")))).isoformat() if expiry_choice == 'y' else "NA"

    secrets_data[domain] = {"domain": domain, "secret": secret, "time_start": start_time, "time_end": end_time}
    save_secrets(secrets_data, password)
    print(f"Secret for {domain} created successfully.")

def get_secret_by_domain(secrets_data, domain):
    secret_data = secrets_data.get(domain)
    if not secret_data:
        print(f"No secret found for domain: {domain}")
    else:
        print(f"Domain: {domain}\nSecret: {secret_data['secret']}\nStart Time: {secret_data['time_start']}\nEnd Time: {secret_data['time_end']}")

def show_all_secrets(secrets_data):
    if not secrets_data:
        print("No secrets stored.")
        return
    for domain, data in secrets_data.items():
        print(f"Domain: {domain}\nSecret: {data['secret']}\nStart Time: {data['time_start']}\nEnd Time: {data['time_end']}\n")

def show_all_domains(secrets_data):
    if not secrets_data:
        print("No domains stored.")
        return
    for domain in secrets_data.keys():
        print(f"Domain: {domain}")

def delete_secret_by_domain(secrets_data, domain, password):
    if domain in secrets_data:
        del secrets_data[domain]
        save_secrets(secrets_data, password)
        print(f"Secret for {domain} deleted.")
    else:
        print(f"No secret found for domain: {domain}")

def rotate_secret_by_domain(secrets_data, domain, password):
    if domain in secrets_data:
        new_secret = secrets.token_hex(16)  # Generate a new 16-byte hex secret
        secrets_data[domain]['secret'] = new_secret
        secrets_data[domain]['time_start'] = datetime.datetime.now().isoformat()
        save_secrets(secrets_data, password)
        print(f"Secret for {domain} rotated.")
    else:
        print(f"No secret found for domain: {domain}")

def check_and_rotate_expired_secrets(secrets_data, password):
    expired_domains = []
    for domain, data in secrets_data.items():
        if data['time_end'] != "NA" and datetime.datetime.fromisoformat(data['time_end']) <= datetime.datetime.now():
            expired_domains.append(domain)
            os.makedirs(BACKUP_DIR, exist_ok=True)
            backup_file = os.path.join(BACKUP_DIR, f"{domain}_backup.json")
            with open(backup_file, 'w') as f:
                json.dump(data, f)
            print(f"Secret for {domain} backed up to {backup_file}.")
            rotate_secret_by_domain(secrets_data, domain, password)

    if not expired_domains:
        print("No expired secrets found.")
    else:
        print("Expired secrets rotated and backed up.")

def check_enrollment():
    if not os.path.exists(SECRET_FILE):
        print("No existing secrets found. Please start enrollment.")
        return False
    return True

# Function to initialize and save an empty secrets file during enrollment
def enroll_new_user():
    password = getpass("Set a password for encryption: ")
    secrets_data = {}
    save_secrets(secrets_data, password)
    print("Enrollment completed. You may now manage your secrets.")
    return secrets_data, password


def export_secrets_unciphered(secrets_data):
    print("WARNING: This will export all secrets to an unencrypted JSON file.")
    confirm = input("Are you sure you want to proceed? (Y/N): ").strip().lower()
    if confirm == 'y':
        with open(UNCIPHERED_EXPORT_FILE, 'w') as f:
            json.dump(secrets_data, f, indent=4)
        print(f"Secrets have been exported to {UNCIPHERED_EXPORT_FILE} as plain text.")
    else:
        print("Export canceled.")

def load_secrets_with_retries():
    """Load secrets with up to 5 password retries."""
    for attempt in range(5):
        password = getpass("Enter your password: ")
        try:
            secrets_data = load_secrets(password)
            if secrets_data is not None:
                return secrets_data, password
        except InvalidTag:
            print("Invalid password. Try again.")
    print("Exceeded maximum password attempts. Try another time.")
    return None, None

def load_secrets_with_retries():
    """Load secrets with up to 5 password retries."""
    for attempt in range(5):
        password = getpass("Enter your password: ")
        try:
            secrets_data = load_secrets(password)
            if secrets_data is not None:
                return secrets_data, password
        except InvalidTag:
            print("Invalid password. Try again.")
    print("Exceeded maximum password attempts. Try another time.")
    return None, None

def show_menu():
    print("\nSecrets Management Menu:")
    print("1. Create a secret")
    print("2. Get secret by domain")
    print("3. Show all secrets")
    print("4. Show all domains")
    print("5. Delete secret by domain")
    print("6. Rotate secret by domain")
    print("7. Check and rotate expired secrets")
    print("8. Export all secrets (unciphered)")
    print("X|x. Exit")

def main_menu():
    secrets_data = None
    password = None

    # Check if enrollment is needed
    if not check_enrollment():
        secrets_data, password = enroll_new_user()
        show_menu()
    else:
        # Show the menu first if the directory exists
        show_menu()
        choice = input("Do you want to access your secrets? (Y/N): ").strip().lower()
        if choice == 'y':
            secrets_data, password = load_secrets_with_retries()
            if secrets_data is None:
                return  # Exit if loading fails

    # Main loop for managing secrets
    while True:
        if secrets_data is not None:
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                create_secret(secrets_data, password)

            elif choice == '2':
                domain = input("Enter domain name: ")
                get_secret_by_domain(secrets_data, domain)

            elif choice == '3':
                show_all_secrets(secrets_data)

            elif choice == '4':
                show_all_domains(secrets_data)

            elif choice == '5':
                domain = input("Enter domain name to delete: ")
                delete_secret_by_domain(secrets_data, domain, password)

            elif choice == '6':
                domain = input("Enter domain name to rotate: ")
                rotate_secret_by_domain(secrets_data, domain, password)

            elif choice == '7':
                check_and_rotate_expired_secrets(secrets_data, password)

            elif choice == '8':
                export_secrets_unciphered(secrets_data)

            elif choice == 'X' or choice == 'x':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")
        else:
            break  # Exit if no secrets were loaded

if __name__ == "__main__":
    main_menu()

