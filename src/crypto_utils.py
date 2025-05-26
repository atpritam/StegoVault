"""
Cryptographic utilities for encrypting and decrypting messages in steganography.
"""

import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoManager:
    """Handles encryption and decryption of messages for steganography."""

    def __init__(self):
        self.SALT_SIZE = 16  # 16 bytes for salt
        self.KEY_ITERATIONS = 100000  # PBKDF2 iterations

    def derive_key(self, password, salt):
        """
        Derive encryption key from password using PBKDF2.

        Args:
            password (str): Password for key derivation
            salt (bytes): Salt for key derivation

        Returns:
            bytes: Derived key suitable for Fernet encryption
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.KEY_ITERATIONS
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.urlsafe_b64encode(key)

    def encrypt_message(self, message, password):
        """
        Encrypt a message with a password.

        Args:
            message (str): Plain text message to encrypt
            password (str): Password for encryption

        Returns:
            bytes: Salt + encrypted message
        """
        # random salt
        salt = secrets.token_bytes(self.SALT_SIZE)

        # Derive key from password
        key = self.derive_key(password, salt)

        # Fernet cipher and encrypt
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode('utf-8'))

        return salt + encrypted_message

    def decrypt_message(self, encrypted_data, password):
        """
        Decrypt a message with a password.

        Args:
            encrypted_data (bytes): Salt + encrypted message
            password (str): Password for decryption

        Returns:
            str: Decrypted plain text message

        Raises:
            ValueError: If decryption fails (wrong password or corrupted data)
        """
        if len(encrypted_data) < self.SALT_SIZE:
            raise ValueError("Encrypted data too short to contain salt")

        # Extract salt and encrypted message
        salt = encrypted_data[:self.SALT_SIZE]
        encrypted_message = encrypted_data[self.SALT_SIZE:]

        # Derive key from password
        key = self.derive_key(password, salt)

        # Fernet cipher and decrypt
        fernet = Fernet(key)

        try:
            decrypted_message = fernet.decrypt(encrypted_message)
            return decrypted_message.decode('utf-8')
        except Exception as e:
            raise ValueError("Decryption failed - invalid password or corrupted data") from e

    def encrypt_bytes(self, data, password):
        """
        Encrypt raw bytes with a password.

        Args:
            data (bytes): Raw data to encrypt
            password (str): Password for encryption

        Returns:
            bytes: Salt + encrypted data
        """
        # random salt
        salt = secrets.token_bytes(self.SALT_SIZE)

        # Derive key from password
        key = self.derive_key(password, salt)

        # Fernet cipher and encrypt
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)

        return salt + encrypted_data

    def decrypt_bytes(self, encrypted_data, password):
        """
        Decrypt raw bytes with a password.

        Args:
            encrypted_data (bytes): Salt + encrypted data
            password (str): Password for decryption

        Returns:
            bytes: Decrypted raw data

        Raises:
            ValueError: If decryption fails (wrong password or corrupted data)
        """
        if len(encrypted_data) < self.SALT_SIZE:
            raise ValueError("Encrypted data too short to contain salt")

        # Extract salt and encrypted data
        salt = encrypted_data[:self.SALT_SIZE]
        encrypted_content = encrypted_data[self.SALT_SIZE:]

        # Derive key from password
        key = self.derive_key(password, salt)

        # Fernet cipher and decrypt
        fernet = Fernet(key)

        try:
            return fernet.decrypt(encrypted_content)
        except Exception as e:
            raise ValueError("Decryption failed - invalid password or corrupted data") from e

    def validate_password_strength(self, password):
        """
        Validate password strength and provide feedback.

        Args:
            password (str): Password to validate

        Returns:
            tuple: (is_strong, strength_score, feedback_message)
        """
        if not password:
            return False, 0, "Password cannot be empty"

        score = 0
        feedback = []

        # Length check
        if len(password) >= 8:
            score += 2
        elif len(password) >= 6:
            score += 1
        else:
            feedback.append("Use at least 6 characters")

        # Character variety checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if has_lower:
            score += 1
        if has_upper:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1

        if score < 3:
            strength = "Weak"
            if not has_upper and not has_lower:
                feedback.append("Include letters")
            if not has_digit:
                feedback.append("Include numbers")
        elif score < 5:
            strength = "Medium"
            if not has_special:
                feedback.append("Consider special characters")
        else:
            strength = "Strong"
            feedback.append("Good password strength")

        is_strong = score >= 4
        message = f"{strength}: {', '.join(feedback)}" if feedback else strength

        return is_strong, score, message

    def generate_secure_password(self, length=12):
        """
        Generate a cryptographically secure random password.

        Args:
            length (int): Desired password length (minimum 8)

        Returns:
            str: Randomly generated password
        """
        if length < 8:
            length = 8

        # Character sets
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        special = "!@#$%^&*()_+-="

        all_chars = lowercase + uppercase + digits + special

        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))

        # shuffle password
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def is_encrypted_data(self, data):
        """
        Attempt to determine if data appears to be encrypted.

        Args:
            data (bytes): Data to analyze

        Returns:
            bool: True if data appears encrypted, False otherwise
        """
        if len(data) < self.SALT_SIZE + 32:
            return False

        try:
            data.decode('utf-8')
            return False
        except UnicodeDecodeError:
            return True