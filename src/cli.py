"""
StegoVault CLI - Command Line Interface

Usage:
    python cli.py hide <image> <message> [options]
    python cli.py extract <image> [options]
    python cli.py info <image>
    python cli.py generate-password [length]
"""

import sys
import os
import argparse
import getpass
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from steganography import SteganographyEngine
    from crypto_utils import CryptoManager
    from PIL import Image
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("Please install required packages: pip install -r requirements.txt")
    sys.exit(1)

class StegoVaultCLI:

    def __init__(self):
        self.stego_engine = SteganographyEngine()
        self.crypto_manager = CryptoManager()

    def validate_image_file(self, image_path):
        """Validate image file exists and is suitable for steganography."""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image file not found: {image_path}")

        is_valid, message = self.stego_engine.validate_image(image_path)
        if not is_valid:
            raise ValueError(f"Invalid image: {message}")

        return True

    def read_message_input(self, message_input):
        """Read message from text input or file."""
        if os.path.isfile(message_input):
            try:
                with open(message_input, 'r', encoding='utf-8') as f:
                    return f.read()
            except UnicodeDecodeError:
                # reading as binary and convert to text
                with open(message_input, 'rb') as f:
                    return f.read().decode('utf-8', errors='replace')
        else:
            return message_input

    def get_password(self, confirm=False):
        """Securely get password from user."""
        try:
            password = getpass.getpass("Enter password: ")
            if confirm:
                confirm_pwd = getpass.getpass("Confirm password: ")
                if password != confirm_pwd:
                    raise ValueError("Passwords don't match!")
            return password
        except KeyboardInterrupt:
            print("\n❌ Operation cancelled")
            sys.exit(1)

    def validate_password_strength(self, password):
        is_strong, score, message = self.crypto_manager.validate_password_strength(password)
        if not is_strong:
            print(f"⚠️  Password strength: {message}")
            response = input("Continue anyway? (y/N): ").lower()
            if response != 'y':
                print("❌ Operation cancelled")
                sys.exit(1)
        else:
            print(f"✅ Password strength: {message}")

    def hide_message(self, args):
        """Hide a message in an image."""
        try:
            # Validate inputs
            print(f"📂 Loading image: {args.image}")
            self.validate_image_file(args.image)
            image = Image.open(args.image)

            # Get image info
            info = self.stego_engine.get_image_info(image)
            print(f"📊 Image: {info['width']}×{info['height']} | Capacity: {info['capacity_bytes']:,} bytes")

            # Read message
            print(f"📝 Reading message: {args.message}")
            message = self.read_message_input(args.message)
            message_size = len(message.encode('utf-8'))

            print(f"📏 Message size: {message_size:,} bytes")

            # Check capacity
            if message_size > info['capacity_bytes']:
                raise ValueError(
                    f"Message too large! Max: {info['capacity_bytes']:,} bytes, Got: {message_size:,} bytes")

            # Handle password
            password = None
            if args.password:
                if args.password == "prompt":
                    password = self.get_password(confirm=True)
                    self.validate_password_strength(password)
                else:
                    password = args.password
                    self.validate_password_strength(password)

            # Process message
            if password:
                print("🔐 Encrypting message...")
                encrypted_data = self.crypto_manager.encrypt_message(message, password)
                print("📦 Embedding encrypted message...")
                result_image = self.stego_engine.hide_bytes(image, encrypted_data)
            else:
                print("📦 Embedding message...")
                result_image = self.stego_engine.hide_text(image, message)

            # Save result
            output_path = args.output or self.generate_output_filename(args.image)
            print(f"💾 Saving to: {output_path}")
            result_image.save(output_path)

            print("✅ Message hidden successfully!")

            return True

        except Exception as e:
            print(f"❌ Error hiding message: {e}")
            return False

    def extract_message(self, args):
        """Extract a hidden message from an image."""
        try:
            # Validate image
            print(f"📂 Loading image: {args.image}")
            if not os.path.exists(args.image):
                raise FileNotFoundError(f"Image file not found: {args.image}")

            image = Image.open(args.image)

            # Extract raw data
            print("🔍 Scanning for hidden data...")
            extracted_data = self.stego_engine.extract_data_lsb(image)

            if not extracted_data:
                print("❌ No hidden message found in this image")
                return False

            # decode as text first
            try:
                message = extracted_data.decode('utf-8')
                print("✅ Message extracted successfully!")
                self.display_extracted_message(message, args.output)
                return True
            except UnicodeDecodeError:
                # Check if encrypted
                if self.crypto_manager.is_encrypted_data(extracted_data):
                    print("🔐 Message appears to be encrypted")

                    # Get password
                    if args.password:
                        password = args.password if args.password != "prompt" else self.get_password()
                    else:
                        password = self.get_password()

                    # Decrypt
                    print("🔓 Decrypting message...")
                    try:
                        message = self.crypto_manager.decrypt_message(extracted_data, password)
                        print("✅ Message decrypted successfully!")
                        self.display_extracted_message(message, args.output)
                        return True
                    except Exception as e:
                        print(f"❌ Decryption failed: Invalid password or corrupted data")
                        return False
                else:
                    print("❌ Found data but cannot decode as text")
                    return False

        except Exception as e:
            print(f"❌ Error extracting message: {e}")
            return False

    def display_extracted_message(self, message, output_file=None):
        """Display or save extracted message."""
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(message)
            print(f"💾 Message saved to: {output_file}")
        else:
            print("\n" + "=" * 50)
            print("📄 EXTRACTED MESSAGE:")
            print("=" * 50)
            print(message)
            print("=" * 50)

    def show_image_info(self, args):
        """Show detailed image information and capacity."""
        try:
            print(f"📂 Analyzing image: {args.image}")
            self.validate_image_file(args.image)

            image = Image.open(args.image)
            info = self.stego_engine.get_image_info(image)

            print("\n" + "=" * 50)
            print("📊 IMAGE INFORMATION:")
            print("=" * 50)
            print(f"File: {os.path.basename(args.image)}")
            print(f"Format: {image.format}")
            print(f"Mode: {info['mode']}")
            print(f"Dimensions: {info['width']} × {info['height']} pixels")
            print(f"Total pixels: {info['total_pixels']:,}")
            print(f"File size: {os.path.getsize(args.image):,} bytes")
            print(f"\nSteganography capacity:")
            print(f"  Max message size: {info['capacity_bytes']:,} bytes")
            print(f"  Max message size: {info['capacity_kb']:.2f} KB")
            if info['capacity_kb'] > 1024:
                print(f"  Max message size: {info['capacity_kb'] / 1024:.2f} MB")
            print("=" * 50)

            return True

        except Exception as e:
            print(f"❌ Error analyzing image: {e}")
            return False

    def generate_password(self, args):
        """Generate a secure password."""
        length = args.length or 12
        if length < 8:
            print("⚠️  Minimum password length is 8 characters")
            length = 8

        password = self.crypto_manager.generate_secure_password(length)
        is_strong, score, message = self.crypto_manager.validate_password_strength(password)

        print(f"🎲 Generated password: {password}")
        print(f"🔒 Strength: {message}")
        print("⚠️  Save this password securely - you'll need it to decrypt your message!")

        return True

    def generate_output_filename(self, input_path):
        """Generate output filename for hidden message image."""
        path = Path(input_path)
        stem = path.stem
        suffix = path.suffix
        return str(path.parent / f"{stem}_with_message{suffix}")


def create_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hide a text message
  python cli.py hide image.png "Secret message" -o output.png

  # Hide message from file with password
  python cli.py hide image.png message.txt -p prompt -o secret.png

  # Extract encrypted/non-encrypted message 
  python cli.py extract secret.png

  # Extract encrypted message to output file
  python cli.py extract secret.png -p prompt -o extracted.txt
  
  # Extract encrypted message with password
  python app.py cli extract image.png -p "mypassword"

  # Show image capacity
  python cli.py info image.png

  # Generate secure password
  python cli.py generate-password
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Hide command
    hide_parser = subparsers.add_parser('hide', help='Hide a message in an image')
    hide_parser.add_argument('image', help='Input image file (PNG or BMP)')
    hide_parser.add_argument('message', help='Message text or path to message file')
    hide_parser.add_argument('-o', '--output', help='Output image file (default: auto-generated)')
    hide_parser.add_argument('-p', '--password', help='Password for encryption (use "prompt" for secure input)')

    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract hidden message from image')
    extract_parser.add_argument('image', help='Image file with hidden message')
    extract_parser.add_argument('-p', '--password', help='Password for decryption (use "prompt" for secure input)')
    extract_parser.add_argument('-o', '--output', help='Save extracted message to file')

    # Info command
    info_parser = subparsers.add_parser('info', help='Show image information and capacity')
    info_parser.add_argument('image', help='Image file to analyze')

    # Generate password command
    gen_parser = subparsers.add_parser('generate-password', help='Generate a secure password')
    gen_parser.add_argument('length', type=int, nargs='?', default=12, help='Password length (default: 12)')

    return parser


def main():
    parser = create_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    cli = StegoVaultCLI()

    success = False

    try:
        if args.command == 'hide':
            success = cli.hide_message(args)
        elif args.command == 'extract':
            success = cli.extract_message(args)
        elif args.command == 'info':
            success = cli.show_image_info(args)
        elif args.command == 'generate-password':
            success = cli.generate_password(args)
        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()