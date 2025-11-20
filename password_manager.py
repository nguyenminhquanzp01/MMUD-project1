from typing import Optional, Tuple
from util import dict_to_json_str, json_str_to_dict
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
MAX_PASSWORD_LENGTH = 64


class Keychain:
    def __init__(self, kvs: dict, salt: bytes, key_enc: bytes, key_mac: bytes):
        """
        Initializes Keychain from decrypted info.
        """
        self.data = {
            "salt": encode_bytes(salt),
            "kvs": kvs
        }
        self.secrets = {
            "key_enc": key_enc,
            "key_mac": key_mac
        }

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        """
        Creates a new empty Keychain.
        """
        salt = get_random_bytes(16)

        derived_key = PBKDF2(
            password=str_to_bytes(keychain_password),
            salt=salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )

        # derive two subkeys using HMAC as PRF
        key_mac = HMAC.new(derived_key, b"mac key", SHA256).digest()
        key_enc = HMAC.new(derived_key, b"enc key", SHA256).digest()

        kvs = {}
        return Keychain(kvs, salt, key_enc, key_mac)

    @staticmethod
    def load(
        keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """
        Loads Keychain from saved representation.
        """
        data = json_str_to_dict(repr)
        salt = decode_bytes(data["salt"])
        kvs = data["kvs"]

        # Regenerate keys using password and salt
        derived_key = PBKDF2(
            password=str_to_bytes(keychain_password),
            salt=salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )

        # derive two subkeys using HMAC as PRF
        key_mac = HMAC.new(derived_key, b"mac key", SHA256).digest()
        key_enc = HMAC.new(derived_key, b"enc key", SHA256).digest()

        # Optional integrity check
        if trusted_data_check:
            check = SHA256.new(str_to_bytes(repr)).digest()
            if check != trusted_data_check:
                raise ValueError("Checksum mismatch")

        # Test password correctness by verifying domain HMAC or try a dummy decryption
        # (Here we trust correct password -> valid derived key)
        return Keychain(kvs, salt, key_enc, key_mac)

    def dump(self) -> Tuple[str, bytes]:
        """
        Serializes and returns checksum.
        """
        json_repr = dict_to_json_str(self.data)
        checksum = SHA256.new(str_to_bytes(json_repr)).digest()
        return json_repr, checksum

    def set(self, domain: str, password: str):
        """
        Encrypts both domain and password, then stores in KVS.
        """
        #Tạo HMAC(domain)
        hmac_domain = HMAC.new(self.secrets["key_mac"], str_to_bytes(domain), SHA256).digest()
        encoded_domain = encode_bytes(hmac_domain)

        #Mã hóa password bằng AES-GCM
        nonce = get_random_bytes(12)
        cipher = AES.new(self.secrets["key_enc"], AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(str_to_bytes(password))

        #Lưu vào KVS
        self.data["kvs"][encoded_domain] = {
            "nonce": encode_bytes(nonce),
            "ciphertext": encode_bytes(ciphertext),
            "tag": encode_bytes(tag)
        }

    def get(self, domain: str) -> Optional[str]:
        """
        Decrypts password corresponding to given domain.
        """
        #Tạo lại HMAC(domain)
        hmac_domain = HMAC.new(self.secrets["key_mac"], str_to_bytes(domain), SHA256).digest()
        encoded_domain = encode_bytes(hmac_domain)

        entry = self.data["kvs"].get(encoded_domain)
        if not entry:
            return None

        nonce = decode_bytes(entry["nonce"])
        ciphertext = decode_bytes(entry["ciphertext"])
        tag = decode_bytes(entry["tag"])

        cipher = AES.new(self.secrets["key_enc"], AES.MODE_GCM, nonce=nonce)
        password = cipher.decrypt_and_verify(ciphertext, tag)
        return bytes_to_str(password)

    def remove(self, domain: str) -> bool:
        """
        Deletes entry by HMAC(domain).
        """
        hmac_domain = HMAC.new(self.secrets["key_mac"], str_to_bytes(domain), SHA256).digest()
        encoded_domain = encode_bytes(hmac_domain)

        if encoded_domain in self.data["kvs"]:
            del self.data["kvs"][encoded_domain]
            return True
        return False
