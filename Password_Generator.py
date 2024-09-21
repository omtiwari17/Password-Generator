import random
import string
import tkinter as tk
from tkinter import messagebox
import pyperclip

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Advanced Password Generator")
        
        # Set window size and center it on the screen
        window_width = 500
        window_height = 500
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        position_top = int(screen_height / 2 - window_height / 2)
        position_right = int(screen_width / 2 - window_width / 2)
        master.geometry(f"{window_width}x{window_height}+{position_right}+{position_top}")

        # Title Label
        self.label = tk.Label(master, text="Password Generator", font=("Helvetica", 18, "bold"))
        self.label.pack(pady=20)

        # Password Complexity Options
        self.length_label = tk.Label(master, text="Select Password Length:", font=("Helvetica", 12))
        self.length_label.pack(pady=5)

        self.length_scale = tk.Scale(master, from_=8, to_=32, orient="horizontal", font=("Helvetica", 10), length=300)
        self.length_scale.pack(pady=5)

        self.include_upper = tk.BooleanVar()
        self.uppercase_checkbox = tk.Checkbutton(
            master, text="Include Uppercase Letters", variable=self.include_upper, font=("Helvetica", 10)
        )
        self.uppercase_checkbox.pack()

        self.include_numbers = tk.BooleanVar()
        self.numbers_checkbox = tk.Checkbutton(
            master, text="Include Numbers", variable=self.include_numbers, font=("Helvetica", 10)
        )
        self.numbers_checkbox.pack()

        self.include_special = tk.BooleanVar()
        self.special_checkbox = tk.Checkbutton(
            master, text="Include Special Characters", variable=self.include_special, font=("Helvetica", 10)
        )
        self.special_checkbox.pack()

        # Exclude characters input
        self.exclude_label = tk.Label(master, text="Exclude Characters (optional):", font=("Helvetica", 12))
        self.exclude_label.pack(pady=5)
        self.exclude_entry = tk.Entry(master, width=30)
        self.exclude_entry.pack(pady=5)

        # Generate Button
        self.generate_button = tk.Button(
            master, text="Generate Password", command=self.generate_password, font=("Helvetica", 12), width=20, height=2
        )
        self.generate_button.pack(pady=15)

        # Display generated password
        self.password_display = tk.Entry(master, width=40, font=("Helvetica", 14), justify='center')
        self.password_display.pack(pady=10)

        # Copy to Clipboard Button (same size as Generate button)
        self.copy_button = tk.Button(
            master, text="Copy to Clipboard", command=self.copy_to_clipboard, font=("Helvetica", 12), width=20, height=2
        )
        self.copy_button.pack(pady=10)

    def generate_password(self):
        length = self.length_scale.get()

        # Validate Input
        error_message = self.validate_input(length)
        if error_message:
            messagebox.showwarning("Input Error", error_message)
            return

        # Get character set and apply customizations
        char_set = self.get_character_set(self.include_upper.get(), self.include_numbers.get(), self.include_special.get())
        exclude_chars = self.exclude_entry.get()
        if exclude_chars:
            char_set = self.customize_character_set(char_set, exclude_chars)

        password = ''.join(random.choice(char_set) for _ in range(length))

        # Ensure password meets security rules
        if not self.password_meets_security_rules(password, self.include_upper.get(), self.include_numbers.get(), self.include_special.get()):
            self.generate_password()  # Re-generate password if it fails security rules
        else:
            self.password_display.delete(0, tk.END)
            self.password_display.insert(0, password)

    def validate_input(self, length):
        if length < 8 or length > 32:
            return "Password length must be between 8 and 32 characters!"
        if not (self.include_upper.get() or self.include_numbers.get() or self.include_special.get()):
            return "Please select at least one character type!"
        return None

    def get_character_set(self, include_upper, include_numbers, include_special):
        char_set = string.ascii_lowercase
        if include_upper:
            char_set += string.ascii_uppercase
        if include_numbers:
            char_set += string.digits
        if include_special:
            char_set += string.punctuation
        return char_set

    def customize_character_set(self, char_set, exclude_chars):
        return ''.join(char for char in char_set if char not in exclude_chars)

    def password_meets_security_rules(self, password, include_upper, include_numbers, include_special):
        if include_upper and not any(char.isupper() for char in password):
            return False
        if include_numbers and not any(char.isdigit() for char in password):
            return False
        if include_special and not any(char in string.punctuation for char in password):
            return False
        return True

    def copy_to_clipboard(self):
        password = self.password_display.get()  
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "No password to copy!")


if __name__ == "__main__":
    root = tk.Tk()
    password_gen = PasswordGenerator(root)
    root.mainloop()
