"""
GUI interface for the steganography application.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk
import os
from steganography import SteganographyEngine
from crypto_utils import CryptoManager


class SteganographyGUI:
    """Main GUI class for the steganography application."""

    def __init__(self):

        self.stego_engine = SteganographyEngine()
        self.crypto_manager = CryptoManager()

        # Initialize GUI
        self.window = tk.Tk()
        self.window.title("StegoVault - Professional Steganography Tool")
        self.window.geometry("900x600")
        self.window.minsize(1000, 800)
        self.window.configure(bg="#2c3e50")

        # App state
        self.current_screen = None
        self.image_data = {}
        self.message_data = {}

        # main container
        self.main_container = tk.Frame(self.window, bg="#2c3e50")
        self.main_container.pack(fill="both", expand=True)

        self.show_main_menu()

    def clear_screen(self):
        """Clear the current screen"""
        for widget in self.main_container.winfo_children():
            widget.destroy()

    def create_header(self, title, subtitle=""):
        header_frame = tk.Frame(self.main_container, bg="#34495e", height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)

        title_label = tk.Label(header_frame, text=title,
                               font=("Arial", 20, "bold"), fg="white", bg="#34495e")
        title_label.pack(pady=(15, 0))

        if subtitle:
            subtitle_label = tk.Label(header_frame, text=subtitle,
                                      font=("Arial", 11), fg="#bdc3c7", bg="#34495e")
            subtitle_label.pack()

        return header_frame

    def create_progress_bar(self, current_step, total_steps):
        """Create a progress indicator"""
        progress_frame = tk.Frame(self.main_container, bg="#34495e", height=30)
        progress_frame.pack(fill="x")
        progress_frame.pack_propagate(False)

        progress_label = tk.Label(progress_frame, text=f"Step {current_step} of {total_steps}",
                                  font=("Arial", 10), fg="white", bg="#34495e")
        progress_label.pack(side="right", padx=20, pady=8)

        # Progress bar
        progress_container = tk.Frame(progress_frame, bg="#34495e")
        progress_container.pack(side="left", padx=20, pady=8)

        for i in range(total_steps):
            color = "#27ae60" if i < current_step else "#7f8c8d"
            step_frame = tk.Frame(progress_container, bg=color, width=30, height=14)
            step_frame.pack(side="left", padx=2)
            step_frame.pack_propagate(False)

    def create_navigation(self, back_cmd, back_text, next_cmd, next_text):
        """Create navigation buttons"""
        nav_frame = tk.Frame(self.main_container, bg="#2c3e50", height=60)
        nav_frame.pack(fill="x", side="bottom")
        nav_frame.pack_propagate(False)

        # Back button
        back_btn = tk.Button(nav_frame, text=back_text, command=back_cmd,
                             bg="#7f8c8d", fg="white", font=("Arial", 11, "bold"),
                             width=15, cursor="hand2")
        back_btn.pack(side="left", padx=20, pady=15)

        # Next button
        next_state = "normal" if next_cmd else "disabled"
        self.next_btn = tk.Button(nav_frame, text=next_text, command=next_cmd,
                                  bg="#27ae60", fg="white", font=("Arial", 11, "bold"),
                                  width=20, state=next_state, cursor="hand2")
        self.next_btn.pack(side="right", padx=20, pady=15)

    # MAIN MENU
    def show_main_menu(self):
        """Main menu screen"""
        self.clear_screen()
        self.current_screen = "main_menu"

        # Header
        self.create_header("🔐 StegoVault")

        # Content area
        content = tk.Frame(self.main_container, bg="#2c3e50")
        content.pack(fill="both", expand=True, padx=40, pady=40)

        # Welcome message
        welcome_frame = tk.Frame(content, bg="#ecf0f1", relief="raised", bd=2)
        welcome_frame.pack(fill="x", pady=(0, 30))

        welcome_label = tk.Label(welcome_frame,
                                 text="Hide messages securely inside images!",
                                 font=("Arial", 12), bg="#ecf0f1", fg="#2c3e50")
        welcome_label.pack(pady=20)

        # Operation buttons
        buttons_frame = tk.Frame(content, bg="#2c3e50")
        buttons_frame.pack(expand=True)

        # Hide Message button
        hide_btn = tk.Button(buttons_frame, text="🔒 Hide a Secret Message",
                             command=self.start_hide_flow,
                             bg="#e74c3c", fg="white", font=("Arial", 14, "bold"),
                             width=25, height=3, cursor="hand2")
        hide_btn.pack(pady=20)

        hide_desc = tk.Label(buttons_frame,
                             text="Embed a secret message inside an image with optional encryption",
                             font=("Arial", 10), fg="#bdc3c7", bg="#2c3e50")
        hide_desc.pack(pady=(0, 30))

        # Extract Message button
        extract_btn = tk.Button(buttons_frame, text="🔓 Extract Hidden Message",
                                command=self.start_extract_flow,
                                bg="#3498db", fg="white", font=("Arial", 14, "bold"),
                                width=25, height=3, cursor="hand2")
        extract_btn.pack(pady=20)

        extract_desc = tk.Label(buttons_frame,
                                text="Retrieve and decrypt hidden messages from images",
                                font=("Arial", 10), fg="#bdc3c7", bg="#2c3e50")
        extract_desc.pack(pady=(0, 30))

    # HIDE MESSAGE WORKFLOW
    def start_hide_flow(self):
        self.image_data = {}
        self.message_data = {}
        self.show_hide_step1()

    def show_hide_step1(self):
        """Hide Flow - Step 1: Load Image"""
        self.clear_screen()
        self.current_screen = "hide_step1"

        self.create_header("🔒 Hide Message - Step 1 of 4", "Select an image to hide your message in")
        self.create_progress_bar(1, 4)

        # Content
        content = tk.Frame(self.main_container, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Instructions
        inst_frame = tk.Frame(content, bg="#3498db", relief="raised", bd=2)
        inst_frame.pack(fill="x", pady=(0, 20))

        tk.Label(inst_frame, text="📋 Instructions: Choose a PNG or BMP image file",
                 font=("Arial", 12, "bold"), fg="white", bg="#3498db").pack(pady=10)

        # Image selection area
        select_frame = tk.Frame(content, bg="white", relief="sunken", bd=2)
        select_frame.pack(fill="both", expand=True)

        # Load button
        load_btn = tk.Button(select_frame, text="📁 Choose Image File",
                             command=self.load_image_hide,
                             bg="#27ae60", fg="white", font=("Arial", 14, "bold"),
                             width=20, height=2, cursor="hand2")
        load_btn.pack(pady=50)

        # Image display area
        self.image_display_frame = tk.Frame(select_frame, bg="white")
        self.image_display_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.image_label = tk.Label(self.image_display_frame,
                                    text="No image selected",
                                    bg="white", fg="#7f8c8d", font=("Arial", 11))
        self.image_label.pack(expand=True)

        # Image info
        self.image_info_label = tk.Label(select_frame, text="",
                                         font=("Arial", 10), bg="white", fg="#2c3e50")
        self.image_info_label.pack(pady=10)

        # Navigation
        self.create_navigation(back_cmd=self.show_main_menu,
                               back_text="🏠 Main Menu",
                               next_cmd=None,
                               next_text="Next: Enter Message")

    def load_image_hide(self):
        """Load image for hiding message"""
        file_path = filedialog.askopenfilename(
            title="Select Image for Hiding Message",
            filetypes=[
                ("PNG files", "*.png"),
                ("BMP files", "*.bmp"),
                ("All supported", "*.png *.bmp")
            ]
        )

        if file_path:
            try:
                # Validate image using steganography engine
                is_valid, message = self.stego_engine.validate_image(file_path)
                if not is_valid:
                    messagebox.showerror("Invalid Image", message)
                    return

                image = Image.open(file_path)
                self.image_data = {
                    'path': file_path,
                    'image': image,
                    'filename': os.path.basename(file_path)
                }

                self.display_loaded_image(image)
                self.show_image_capacity()

                # Enable next button
                self.next_btn.configure(state="normal", command=self.show_hide_step2)

            except Exception as e:
                messagebox.showerror("Error", f"Could not load image: {str(e)}")

    def display_loaded_image(self, image):
        """Display the loaded image"""
        for widget in self.image_display_frame.winfo_children():
            widget.destroy()

        display_image = image.copy()
        display_image.thumbnail((300, 200), Image.Resampling.LANCZOS)

        photo = ImageTk.PhotoImage(display_image)

        img_label = tk.Label(self.image_display_frame, image=photo, bg="white")
        img_label.image = photo
        img_label.pack()

        filename_label = tk.Label(self.image_display_frame,
                                  text=f"📁 {self.image_data['filename']}",
                                  font=("Arial", 10, "bold"), bg="white", fg="#2c3e50")
        filename_label.pack(pady=5)

    def show_image_capacity(self):
        """Calculate and show hiding capacity"""
        image = self.image_data['image']
        info = self.stego_engine.get_image_info(image)

        self.image_data['capacity'] = info['capacity_bytes']

        info_text = f"📊 {info['width']}×{info['height']} | {info['mode']} | "
        info_text += f"Capacity: {info['capacity_bytes']:,} bytes ({info['capacity_kb']:.1f} KB)"
        self.image_info_label.configure(text=info_text)

    def show_hide_step2(self):
        """Hide Flow - Step 2: Enter Message"""
        self.clear_screen()
        self.current_screen = "hide_step2"

        # Header
        self.create_header("🔒 Hide Message - Step 2 of 4", "Enter your secret message")
        self.create_progress_bar(2, 4)

        # Content
        content = tk.Frame(self.main_container, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Instructions
        inst_frame = tk.Frame(content, bg="#3498db", relief="raised", bd=2)
        inst_frame.pack(fill="x", pady=(0, 20))

        capacity = self.image_data['capacity']
        tk.Label(inst_frame, text=f"📋 Enter your message (Max: {capacity:,} characters)",
                 font=("Arial", 12, "bold"), fg="white", bg="#3498db").pack(pady=10)

        # Message input area
        msg_frame = tk.Frame(content, bg="white", relief="sunken", bd=2)
        msg_frame.pack(fill="both", expand=True, pady=(0, 10))

        tk.Label(msg_frame, text="Secret Message:",
                 font=("Arial", 12, "bold"), bg="white", fg="#2c3e50").pack(anchor="w", padx=20, pady=(20, 5))

        text_container = tk.Frame(msg_frame, bg="white")
        text_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.message_text = tk.Text(text_container, font=("Arial", 11), wrap=tk.WORD, height=10)
        scrollbar = tk.Scrollbar(text_container, orient="vertical", command=self.message_text.yview)
        self.message_text.configure(yscrollcommand=scrollbar.set)

        self.message_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Character counter
        self.char_count_label = tk.Label(msg_frame, text="Characters: 0",
                                         font=("Arial", 10), bg="white", fg="#7f8c8d")
        self.char_count_label.pack(anchor="w", padx=20, pady=(0, 10))

        self.message_text.bind('<KeyRelease>', self.update_message_count)

        # Navigation
        self.create_navigation(back_cmd=self.show_hide_step1,
                               back_text="← Back",
                               next_cmd=None,
                               next_text="Next: Security Options")

    def update_message_count(self, event=None):
        """Update character count and validation"""
        text = self.message_text.get("1.0", tk.END)
        char_count = len(text) - 1
        capacity = self.image_data['capacity']

        if char_count > capacity:
            self.char_count_label.configure(text=f"Characters: {char_count} (⚠️ TOO LONG!)", fg="red")
            self.next_btn.configure(state="disabled")
        else:
            self.char_count_label.configure(text=f"Characters: {char_count}", fg="#27ae60")
            if char_count > 0:
                self.next_btn.configure(state="normal", command=self.show_hide_step3)
            else:
                self.next_btn.configure(state="disabled")

    def show_hide_step3(self):
        """Hide Flow - Step 3: Security Options"""
        # Save message BEFORE clearing screen
        self.message_data['text'] = self.message_text.get("1.0", tk.END).strip()

        self.clear_screen()
        self.current_screen = "hide_step3"

        # Header
        self.create_header("🔒 Hide Message - Step 3 of 4", "Choose security options")
        self.create_progress_bar(3, 4)

        # Content
        content = tk.Frame(self.main_container, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Instructions
        inst_frame = tk.Frame(content, bg="#3498db", relief="raised", bd=2)
        inst_frame.pack(fill="x", pady=(0, 20))

        tk.Label(inst_frame, text="📋 Optional: Add password protection for extra security",
                 font=("Arial", 12, "bold"), fg="white", bg="#3498db").pack(pady=10)

        # Security options
        security_frame = tk.Frame(content, bg="white", relief="sunken", bd=2)
        security_frame.pack(fill="both", expand=True)

        # Password option
        self.use_password = tk.BooleanVar()
        pwd_check = tk.Checkbutton(security_frame, text="🔐 Enable Password Protection",
                                   variable=self.use_password, command=self.toggle_password_section,
                                   font=("Arial", 12, "bold"), bg="white", fg="#8e44ad")
        pwd_check.pack(anchor="w", padx=20, pady=20)

        # Password input section (hidden initially)
        self.pwd_section = tk.Frame(security_frame, bg="white")

        # Password row
        pwd_row = tk.Frame(self.pwd_section, bg="white")
        pwd_row.pack(fill="x", padx=20, pady=5)

        tk.Label(pwd_row, text="Password:", font=("Arial", 11), bg="white").pack(side="left")

        pwd_input_frame = tk.Frame(pwd_row, bg="white")
        pwd_input_frame.pack(side="left", padx=(10, 5))

        self.password_entry = tk.Entry(pwd_input_frame, show="*", font=("Arial", 11), width=25)
        self.password_entry.pack(side="left")

        # Show/Hide password toggle
        self.show_password = tk.BooleanVar()
        self.show_pwd_btn = tk.Checkbutton(pwd_input_frame, text="👁", variable=self.show_password,
                                           command=self.toggle_password_visibility, font=("Arial", 8),
                                           bg="white", width=2)
        self.show_pwd_btn.pack(side="left", padx=(2, 0))

        # Confirm password row
        confirm_row = tk.Frame(self.pwd_section, bg="white")
        confirm_row.pack(fill="x", padx=20, pady=5)

        tk.Label(confirm_row, text="Confirm:", font=("Arial", 11), bg="white").pack(side="left")

        self.confirm_entry = tk.Entry(confirm_row, show="*", font=("Arial", 11), width=25)
        self.confirm_entry.pack(side="left", padx=(10, 0))

        # Password strength indicator
        self.pwd_strength = tk.Label(self.pwd_section, text="", font=("Arial", 9), bg="white")
        self.pwd_strength.pack(anchor="w", padx=20, pady=5)

        # Password action buttons
        pwd_actions = tk.Frame(self.pwd_section, bg="white")
        pwd_actions.pack(fill="x", padx=20, pady=10)

        # Generate password button
        gen_btn = tk.Button(pwd_actions, text="🎲 Generate Strong Password",
                            command=self.generate_password,
                            bg="#9b59b6", fg="white", font=("Arial", 9, "bold"))
        gen_btn.pack(side="left", padx=(0, 10))

        # Copy password button
        self.copy_pwd_btn = tk.Button(pwd_actions, text="📋 Copy Password",
                                      command=self.copy_password,
                                      bg="#2ecc71", fg="white", font=("Arial", 9, "bold"),
                                      state="disabled")
        self.copy_pwd_btn.pack(side="left", padx=(0, 10))

        # Security warning
        warning_frame = tk.Frame(self.pwd_section, bg="#fff3cd", relief="ridge", bd=1)
        warning_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(warning_frame,
                 text="⚠️ Important: Save your password securely! Without it, you cannot decrypt your message.",
                 font=("Arial", 9, "bold"), bg="#fff3cd", fg="#856404", wraplength=400).pack(pady=8)

        # validation
        self.password_entry.bind('<KeyRelease>', self.validate_password)
        self.confirm_entry.bind('<KeyRelease>', self.validate_password)

        # Summary
        summary_frame = tk.Frame(security_frame, bg="#f8f9fa", relief="ridge", bd=1)
        summary_frame.pack(fill="x", padx=20, pady=20)

        tk.Label(summary_frame, text="📋 Summary", font=("Arial", 11, "bold"), bg="#f8f9fa").pack(pady=5)

        summary_text = f"Message: {len(self.message_data['text'])} characters\n"
        summary_text += f"Image: {self.image_data['filename']}\n"
        summary_text += f"Capacity: {self.image_data['capacity']:,} bytes"

        tk.Label(summary_frame, text=summary_text,
                 font=("Arial", 10), bg="#f8f9fa", justify="left").pack(pady=5)

        # Navigation
        self.create_navigation(back_cmd=self.show_hide_step2,
                               back_text="← Back",
                               next_cmd=self.show_hide_step4,
                               next_text="Next: Hide Message")

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password.get():
            self.password_entry.config(show="")
            self.show_pwd_btn.config(text="🙈")
        else:
            self.password_entry.config(show="*")
            self.show_pwd_btn.config(text="👁")

    def toggle_password_section(self):
        """Show/hide password input section"""
        if self.use_password.get():
            self.pwd_section.pack(fill="x", pady=10)
        else:
            self.pwd_section.pack_forget()
            self.password_entry.delete(0, tk.END)
            self.confirm_entry.delete(0, tk.END)

    def generate_password(self):
        """Generate a strong password"""
        password = self.crypto_manager.generate_secure_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.confirm_entry.delete(0, tk.END)
        self.confirm_entry.insert(0, password)
        # Enable password action buttons
        self.copy_pwd_btn.config(state="normal")

        # Validate the password
        self.validate_password()

    def copy_password(self):
        """Copy the generated password to clipboard"""
        if hasattr(self, 'generated_password'):
            self.window.clipboard_clear()
            self.window.clipboard_append(self.generated_password)
            messagebox.showinfo("Password Copy",
                                "Password copied to clipboard!")
        else:
            password = self.password_entry.get()
            if password:
                self.window.clipboard_clear()
                self.window.clipboard_append(password)
                messagebox.showinfo("Password Copied", "Current password copied to clipboard!")
            else:
                messagebox.showwarning("No Password", "No password to copy!")

    def validate_password(self, event=None):
        """Validate password strength and matching"""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password:
            self.pwd_strength.config(text="")
            return

        # crypto manager for validation
        is_strong, score, message = self.crypto_manager.validate_password_strength(password)

        if password != confirm and confirm:
            self.pwd_strength.config(text="Passwords don't match", fg="red")
        elif password == confirm and confirm:
            self.pwd_strength.config(text="✓ " + message, fg="green" if is_strong else "orange")
        else:
            color = "green" if is_strong else "orange" if score > 2 else "red"
            self.pwd_strength.config(text=message, fg=color)

    def show_hide_step4(self):
        """Hide Flow - Step 4: Process and Save"""
        if self.use_password.get():
            password = self.password_entry.get()
            confirm = self.confirm_entry.get()

            is_strong, score, message = self.crypto_manager.validate_password_strength(password)

            if not is_strong:
                response = messagebox.askyesno("Weak Password",
                                               f"Password strength: {message}\nContinue anyway?")
                if not response:
                    return

            if password != confirm:
                messagebox.showerror("Password Mismatch", "Passwords don't match!")
                return

            self.message_data['password'] = password

        self.clear_screen()
        self.current_screen = "hide_step4"

        # Header
        self.create_header("🔒 Hide Message - Step 4 of 4", "Processing and saving your image")
        self.create_progress_bar(4, 4)

        # Content
        content = tk.Frame(self.main_container, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Processing status
        status_frame = tk.Frame(content, bg="white", relief="raised", bd=2)
        status_frame.pack(fill="x", pady=(0, 20))

        self.process_status = tk.Label(status_frame, text="🔄 Processing...",
                                       font=("Arial", 12, "bold"), bg="white", fg="#f39c12")
        self.process_status.pack(pady=20)

        # Process after a short delay to show the UI
        self.window.after(100, self.process_hide_message)

    def process_hide_message(self):
        """Actually hide the message in the image"""
        try:
            # Update status
            self.process_status.config(text="🔄 Preparing message...")
            self.window.update()

            message = self.message_data['text']
            image = self.image_data['image'].copy()

            # Encrypt if password provided
            if 'password' in self.message_data:
                self.process_status.config(text="🔄 Encrypting message...")
                self.window.update()

                encrypted_data = self.crypto_manager.encrypt_message(message, self.message_data['password'])
                self.process_status.config(text="🔄 Embedding encrypted message...")
                self.window.update()

                result_image = self.stego_engine.hide_bytes(image, encrypted_data)
            else:
                self.process_status.config(text="🔄 Embedding message...")
                self.window.update()

                result_image = self.stego_engine.hide_text(image, message)

            # Save file
            self.process_status.config(text="🔄 Saving image...")
            self.window.update()

            # Ask where to save
            save_path = filedialog.asksaveasfilename(
                title="Save Image with Hidden Message",
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("BMP files", "*.bmp")]
            )

            if save_path:
                result_image.save(save_path)
                self.show_hide_success(save_path)
            else:
                self.process_status.config(text="❌ Save cancelled", fg="red")

        except Exception as e:
            self.process_status.config(text=f"❌ Error: {str(e)}", fg="red")
            messagebox.showerror("Error", f"Could not hide message: {str(e)}")

    def show_hide_success(self, save_path):
        self.process_status.config(text="✅ Message hidden successfully!", fg="green")

        success_frame = tk.Frame(self.main_container.winfo_children()[-1], bg="white", relief="raised", bd=2)
        success_frame.pack(fill="both", expand=True, pady=20)

        tk.Label(success_frame, text="🎉 Success!",
                 font=("Arial", 16, "bold"), bg="white", fg="#27ae60").pack(pady=20)

        details_text = f"Your message has been hidden in:\n{save_path}\n\n"
        if 'password' in self.message_data:
            details_text += "🔐 Message is encrypted with your password.\n"
        details_text += "Keep this image safe - your secret is now invisible!"

        tk.Label(success_frame, text=details_text,
                 font=("Arial", 11), bg="white", fg="#2c3e50", justify="center").pack(pady=10)

        # Action buttons
        btn_frame = tk.Frame(success_frame, bg="white")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="🔓 Extract Message",
                  command=self.start_extract_flow,
                  bg="#3498db", fg="white", font=("Arial", 11, "bold")).pack(side="left", padx=10)

        tk.Button(btn_frame, text="🔒 Hide Another Message",
                  command=self.start_hide_flow,
                  bg="#e74c3c", fg="white", font=("Arial", 11, "bold")).pack(side="left", padx=10)

        tk.Button(btn_frame, text="🏠 Main Menu",
                  command=self.show_main_menu,
                  bg="#7f8c8d", fg="white", font=("Arial", 11, "bold")).pack(side="left", padx=10)

    # EXTRACT MESSAGE WORKFLOW
    def start_extract_flow(self):
        """extract message workflow"""
        self.image_data = {}
        self.message_data = {}
        self.show_extract_step1()

    def show_extract_step1(self):
        """Extract Flow - Step 1: Load Image"""
        self.clear_screen()
        self.current_screen = "extract_step1"

        # Header
        self.create_header("🔓 Extract Message - Step 1 of 2", "Select image with hidden message")
        self.create_progress_bar(1, 2)

        # Content
        content = tk.Frame(self.main_container, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Instructions
        inst_frame = tk.Frame(content, bg="#3498db", relief="raised", bd=2)
        inst_frame.pack(fill="x", pady=(0, 20))

        tk.Label(inst_frame, text="📋 Choose an image that contains a hidden message",
                 font=("Arial", 12, "bold"), fg="white", bg="#3498db").pack(pady=10)

        # Image selection
        select_frame = tk.Frame(content, bg="white", relief="sunken", bd=2)
        select_frame.pack(fill="both", expand=True)

        load_btn = tk.Button(select_frame, text="📁 Choose Image File",
                             command=self.load_image_extract,
                             bg="#27ae60", fg="white", font=("Arial", 14, "bold"),
                             width=20, height=2, cursor="hand2")
        load_btn.pack(pady=50)

        self.extract_image_frame = tk.Frame(select_frame, bg="white")
        self.extract_image_frame.pack(fill="both", expand=True, padx=20, pady=20)

        self.extract_image_label = tk.Label(self.extract_image_frame,
                                            text="No image selected",
                                            bg="white", fg="#7f8c8d", font=("Arial", 11))
        self.extract_image_label.pack(expand=True)

        # Navigation
        self.create_navigation(back_cmd=self.show_main_menu,
                               back_text="🏠 Main Menu",
                               next_cmd=None,
                               next_text="Next: Extract Message")

    def load_image_extract(self):
        """Load image for extracting message"""
        file_path = filedialog.askopenfilename(
            title="Select Image with Hidden Message",
            filetypes=[
                ("PNG files", "*.png"),
                ("BMP files", "*.bmp"),
                ("All supported", "*.png *.bmp")
            ]
        )

        if file_path:
            try:
                image = Image.open(file_path)
                self.image_data = {
                    'path': file_path,
                    'image': image,
                    'filename': os.path.basename(file_path)
                }

                # Display image
                for widget in self.extract_image_frame.winfo_children():
                    widget.destroy()

                display_image = image.copy()
                display_image.thumbnail((300, 200), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(display_image)

                img_label = tk.Label(self.extract_image_frame, image=photo, bg="white")
                img_label.image = photo
                img_label.pack()

                tk.Label(self.extract_image_frame, text=f"📁 {self.image_data['filename']}",
                         font=("Arial", 10, "bold"), bg="white", fg="#2c3e50").pack(pady=5)

                # Enable next
                self.next_btn.configure(state="normal", command=self.show_extract_step2)

            except Exception as e:
                messagebox.showerror("Error", f"Could not load image: {str(e)}")

    def show_extract_step2(self):
        """Extract Flow - Step 2: Extract and Display"""
        self.clear_screen()
        self.current_screen = "extract_step2"

        # Header
        self.create_header("🔓 Extract Message - Step 2 of 2", "Extracting your hidden message")
        self.create_progress_bar(2, 2)

        # Content
        content = tk.Frame(self.main_container, bg="#ecf0f1")
        content.pack(fill="both", expand=True, padx=30, pady=20)

        # Processing status
        status_frame = tk.Frame(content, bg="white", relief="raised", bd=2)
        status_frame.pack(fill="x", pady=(0, 20))

        self.extract_status = tk.Label(status_frame, text="🔄 Extracting message...",
                                       font=("Arial", 12, "bold"), bg="white", fg="#f39c12")
        self.extract_status.pack(pady=20)

        # Result area
        self.result_frame = tk.Frame(content, bg="white", relief="sunken", bd=2)
        self.result_frame.pack(fill="both", expand=True)

        # Process extraction
        self.window.after(100, self.process_extract_message)

    def process_extract_message(self):
        """Extract the hidden message"""
        try:
            self.extract_status.config(text="🔄 Scanning image for hidden data...")
            self.window.update()

            # raw data
            image = self.image_data['image']
            extracted_data = self.stego_engine.extract_data_lsb(image)

            if not extracted_data:
                self.extract_status.config(text="❌ No hidden message found", fg="red")
                tk.Label(self.result_frame, text="No hidden message found in this image.",
                         font=("Arial", 12), bg="white", fg="#e74c3c").pack(expand=True)
                return

            # text decode
            self.extract_status.config(text="🔄 Decoding message...")
            self.window.update()

            try:
                # plain text
                message = extracted_data.decode('utf-8')
                self.show_extracted_message(message, encrypted=False)
            except UnicodeDecodeError:
                # Check if it's encrypted data
                if self.crypto_manager.is_encrypted_data(extracted_data):
                    self.extract_status.config(text="🔐 Message appears to be encrypted", fg="orange")
                    self.ask_for_password(extracted_data)
                else:
                    self.extract_status.config(text="❌ Invalid data format", fg="red")
                    tk.Label(self.result_frame, text="Found data but cannot decode as text.",
                             font=("Arial", 12), bg="white", fg="#e74c3c").pack(expand=True)

        except Exception as e:
            self.extract_status.config(text=f"❌ Error: {str(e)}", fg="red")
            tk.Label(self.result_frame, text=f"Error extracting message: {str(e)}",
                     font=("Arial", 12), bg="white", fg="#e74c3c").pack(expand=True)

    def ask_for_password(self, encrypted_data):
        """Ask for password to decrypt message"""
        self.encrypted_data = encrypted_data

        for widget in self.result_frame.winfo_children():
            widget.destroy()

        tk.Label(self.result_frame, text="🔐 Password Required",
                 font=("Arial", 14, "bold"), bg="white", fg="#8e44ad").pack(pady=20)

        tk.Label(self.result_frame, text="This message appears to be encrypted.\nEnter the password to decrypt:",
                 font=("Arial", 11), bg="white", fg="#2c3e50").pack(pady=10)

        pwd_frame = tk.Frame(self.result_frame, bg="white")
        pwd_frame.pack(pady=20)

        tk.Label(pwd_frame, text="Password:", font=("Arial", 11), bg="white").pack()
        self.decrypt_password = tk.Entry(pwd_frame, show="*", font=("Arial", 12), width=30)
        self.decrypt_password.pack(pady=5)

        btn_frame = tk.Frame(pwd_frame, bg="white")
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="🔓 Decrypt", command=self.try_decrypt,
                  bg="#27ae60", fg="white", font=("Arial", 11, "bold")).pack(side="left", padx=5)

        tk.Button(btn_frame, text="❌ Cancel", command=self.show_main_menu,
                  bg="#e74c3c", fg="white", font=("Arial", 11, "bold")).pack(side="left", padx=5)

        self.decrypt_password.focus()
        self.decrypt_password.bind('<Return>', lambda e: self.try_decrypt())

    def try_decrypt(self):
        password = self.decrypt_password.get()
        if not password:
            messagebox.showwarning("No Password", "Please enter a password!")
            return

        try:
            self.extract_status.config(text="🔄 Decrypting message...", fg="#f39c12")
            self.window.update()

            decrypted_message = self.crypto_manager.decrypt_message(self.encrypted_data, password)
            self.show_extracted_message(decrypted_message, encrypted=True)

        except Exception as e:
            self.extract_status.config(text="❌ Invalid password or corrupted data", fg="red")
            messagebox.showerror("Decryption Failed",
                                 "Invalid password or the data is corrupted!\n\n" +
                                 "Make sure you're using the correct password.")

    def show_extracted_message(self, message, encrypted=False):
        for widget in self.result_frame.winfo_children():
            widget.destroy()

        if encrypted:
            self.extract_status.config(text="✅ Message decrypted successfully!", fg="green")
            icon = "🔐"
            title = "Decrypted Message"
        else:
            self.extract_status.config(text="✅ Message extracted successfully!", fg="green")
            icon = "📄"
            title = "Extracted Message"

        tk.Label(self.result_frame, text=f"{icon} {title}",
                 font=("Arial", 14, "bold"), bg="white", fg="#27ae60").pack(pady=20)

        msg_container = tk.Frame(self.result_frame, bg="white")
        msg_container.pack(fill="x", padx=20, pady=(0, 10))

        text_widget = tk.Text(msg_container, font=("Arial", 11), wrap=tk.WORD,
                              bg="#f8f9fa", relief="sunken", bd=2, height=12)
        scrollbar = tk.Scrollbar(msg_container, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        text_widget.insert("1.0", message)
        text_widget.configure(state="disabled")  # Make read-only

        # Action buttons
        btn_frame = tk.Frame(self.result_frame, bg="white")
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="📋 Copy Message",
                  command=lambda: self.copy_to_clipboard(message),
                  bg="#3498db", fg="white", font=("Arial", 11, "bold"),
                  width=15, height=2).pack(side="left", padx=10)

        tk.Button(btn_frame, text="🔓 Extract Another",
                  command=self.start_extract_flow,
                  bg="#e74c3c", fg="white", font=("Arial", 11, "bold"),
                  width=15, height=2).pack(side="left", padx=10)

        tk.Button(btn_frame, text="🏠 Main Menu",
                  command=self.show_main_menu,
                  bg="#7f8c8d", fg="white", font=("Arial", 11, "bold"),
                  width=15, height=2).pack(side="left", padx=10)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.window.clipboard_clear()
        self.window.clipboard_append(text)
        messagebox.showinfo("Copied", "Message copied to clipboard!")

    def run(self):
        """Start the GUI application"""
        self.window.mainloop()