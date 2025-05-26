"""
StegoVault - Professional Steganography Tool
Main application entry point supporting both GUI and CLI modes.

This application allows users to hide secret messages inside images using
steganography techniques and optional encryption for security.

Author: Pritam Chakraborty
Version: 1.0.0
"""

import sys
import os
import argparse
from tkinter import messagebox
import tkinter as tk

# Add both root directory and src directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))


def check_dependencies(cli_mode=False):
    """
    Check if all required dependencies are installed.

    Args:
        cli_mode (bool): Whether running in CLI mode (affects tkinter requirement)

    Returns:
        tuple: (bool, list) - (all_installed, missing_packages)
    """
    required_packages = {
        'PIL': 'Pillow',
        'cryptography': 'cryptography'
    }

    if not cli_mode:
        required_packages['tkinter'] = 'tkinter'

    missing = []

    for module, package in required_packages.items():
        try:
            if module == 'PIL':
                import PIL
                from PIL import Image, ImageTk
            elif module == 'cryptography':
                from cryptography.fernet import Fernet
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
            elif module == 'tkinter':
                import tkinter as tk
                from tkinter import filedialog, messagebox, ttk
        except ImportError:
            missing.append(package)

    return len(missing) == 0, missing


def show_dependency_error(missing_packages, cli_mode=False):
    """
    Show error message for missing dependencies.

    Args:
        missing_packages (list): List of missing package names
        cli_mode (bool): Whether running in CLI mode
    """
    error_msg = "Missing Required Dependencies!\n\n"
    error_msg += "Please install the following packages:\n\n"

    for package in missing_packages:
        error_msg += f"• {package}\n"

    error_msg += "\nInstall with: pip install "
    error_msg += " ".join(pkg for pkg in missing_packages if pkg != 'tkinter')

    if cli_mode or 'tkinter' in missing_packages:
        print("=" * 50)
        print("DEPENDENCY ERROR")
        print("=" * 50)
        print("Missing required dependencies:")
        for package in missing_packages:
            print(f"  • {package}")
        print("\nPlease install missing packages and try again.")
        if 'tkinter' in missing_packages:
            print("Note: tkinter is usually built-in with Python installations")
        print("=" * 50)
    else:
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Dependency Error", error_msg)
            root.destroy()
        except ImportError:
            print("=" * 50)
            print("DEPENDENCY ERROR")
            print("=" * 50)
            print(error_msg.replace('\n\n', '\n'))
            print("=" * 50)


def run_gui():
    print("🖥️  StegoVault GUI")

    try:
        from src.gui import SteganographyGUI
        app = SteganographyGUI()
        app.run()
    except Exception as e:
        error_msg = f"Failed to start GUI application: {str(e)}"
        print(f"❌ {error_msg}")

        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Application Error", error_msg)
            root.destroy()
        except:
            pass

        sys.exit(1)


def run_cli():
    print("⌨️  StegoVault CLI")

    try:
        from src.cli import main as cli_main
        sys.argv.pop(1)
        cli_main()
    except Exception as e:
        print(f"❌ Failed to start CLI application: {str(e)}")
        sys.exit(1)


def create_main_parser():
    parser = argparse.ArgumentParser(
        prog='stegovault',
        description='🔐 StegoVault - Professional Steganography Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Interface Modes:
  gui    - Launch graphical user interface (default)
  cli    - Use command-line interface
  
Examples:
  python app.py             
  python app.py gui           
  python app.py cli hide images/Nudge.png "secret message"
  python app.py cli hide images/Nudge.png hiddenMsg/hidden.txt
  python app.py cli hide images/Nudge.png "Secret" -p "mypassword"
  python app.py cli hide images/Nudge.png "Secret" -o output.png
  python app.py cli extract image.png
  python app.py cli extract image.png -p "mypassword"
  python app.py cli extract image.png -p prompt
  python app.py cli extract image.png -o message.txt
  python app.py cli info image.png
  python app.py cli generate-password
  python app.py cli generate-password 16
        """
    )

    parser.add_argument('mode', nargs='?', default='gui',
                       choices=['gui', 'cli'],
                       help='Interface mode (default: gui)')

    return parser


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ['gui', 'cli']:
        mode = sys.argv[1]
    else:
        mode = 'gui'

    cli_mode = (mode == 'cli')

    # dependencies
    deps_ok, missing = check_dependencies(cli_mode)

    if not deps_ok:
        print("❌ Missing dependencies!")
        show_dependency_error(missing, cli_mode)
        sys.exit(1)

    if mode == 'cli':
        run_cli()
    else:
        run_gui()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Application interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)