import base64
import json
import os
import argparse
import sys
import bcrypt
import tkinter as tk
from tkinter import messagebox, simpledialog


def make_file(file_name, password):
    new_file_name = file_name + ".pass"
    if os.path.isfile(new_file_name):
        print(f"File '{new_file_name}' already exists.")
        return None
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()

    metadata = {"version": "1.0", "type": "pass", "salt": salt_hex, "hash": hashed_password_hex}
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
            if "metadata" in data and "type" in data["metadata"] and data["metadata"]["type"] == "pass":
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
            for entry in data["entries"]:
                if entry["name"] == name:
                    entry["user"] = user
                    entry["password"] = password
                    break

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


def modify_existing_file(file_name):
    if not authenticate(file_name):
        return False
    while True:
        print("What do you want to do?")
        print("0. Go back")
        print("1. Add a new entry")
        print("2. Edit an existing entry")
        print("3. Remove an entry")
        print("4. List all entries")
        choice = input("Enter your choice (0-4): ")
        try:
            choice = int(choice)
            if choice not in [0, 1, 2, 3, 4]:
                print("Invalid choice. Please try again.")
                continue
        except ValueError:
            print("Invalid choice. Please try again.")
            continue
        if choice == 0:
            break
        if choice == 1:
            name = input("Enter the name of the new entry: ")
            user = input("Enter the user for the new entry: ")
            password = input("Enter the password for the new entry: ")
            if add_entry(file_name, name, user, password):
                print("Entry added successfully.")
            else:
                print("Error adding entry.")
        if choice == 2:
            name = input("Enter the name of the entry to edit: ")
            user = input("Enter the new user for the entry: ")
            password = input("Enter the new password for the entry: ")
            if edit_entry(file_name, name, user, password):
                print("Entry edited successfully.")
            else:
                print("Error editing entry.")
        if choice == 3:
            name = input("Enter the name of the entry to remove: ")
            if remove_entry(file_name, name):
                print("Entry removed successfully.")
            else:
                print("Error removing entry.")
        if choice == 4:
            print("\nListing start:")
            list_entries(file_name)
            print("Listing end.\n")


def interactive_main():
    print("Welcome to PassManager")
    while True:
        print("What do you want to do?")
        print("0. Quit the program")
        print("1. Create a new .pass file")
        print("2. Open existing .pass file")
        choice = input("Enter your choice (1 or 2): ")
        try:
            choice = int(choice)
            if choice not in [0, 1, 2]:
                print("Invalid choice. Please try again.")
        except ValueError:
            print("Invalid choice. Please try again.")
            continue
        if choice == 0:
            break
        if choice == 1:
            file_name = input("Enter the name of the new file (without .pass extension): ")
            password = input("Enter the password for the new file: ")
            file_name = make_file(file_name, password)
            if file_name is not None:
                print(f"File '{file_name}' created successfully.")
        if choice == 2:
            existing_file = input("Enter the name of the existing .pass file (with .pass extension): ")
            if check_file_type(existing_file):
                modify_existing_file(existing_file)
            else:
                print("Invalid file type or file does not exist.")


def arguments_main(args, argparser):
    if args.new:
        file_name = make_file(args.new[0], args.new[1])
        if file_name is not None:
            print(f"File '{file_name}' created successfully.")

    if args.add:
        if not authenticate(args.add[0]):
            return
        if add_entry(args.add[0], args.add[1], args.add[2], args.add[3]):
            print("Entry added successfully.")
        else:
            print("Error adding entry.")
    elif args.edit:
        if not authenticate(args.edit[0]):
            return
        if edit_entry(args.edit[0], args.edit[1], args.edit[2], args.edit[3]):
            print("Entry edited successfully.")
        else:
            print("Error editing entry.")
    elif args.remove:
        if not authenticate(args.remove[0]):
            return
        if remove_entry(args.remove[0], args.remove[1]):
            print("Entry removed successfully.")
        else:
            print("Error removing entry.")
    elif args.list:
        if not authenticate(args.list[0]):
            return
        list_entries(args.list[0])
    else:
        argparser.print_help()



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

def authenticate(file_name):
    for i in range(3):
        password = input("Enter the password for the file: ")
        if authenticate_core(file_name, password):
            return True
        elif i == 2:
            print("Password incorrect. Authentication unsuccessful")
            return False
        else:
            print("Incorrect password. Please try again.")
class AuthenticationWindow:
    def __init__(self, root, file_name):
        self.root = root
        self.root.title("Authentication")
        self.file_name = file_name

        self.label = tk.Label(root, text="Enter Password:")
        self.label.pack(pady=10)

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=10)

        self.submit_button = tk.Button(root, text="Submit", command=self.submit_password)
        self.submit_button.pack(pady=10)

    def submit_password(self):
        password = self.password_entry.get()
        if authenticate_core(self.file_name, password):
            self.root.destroy()
            ListWindow(self.file_name)
        else:
            messagebox.showerror("Error", "Invalid password")


class ListWindow:
    def __init__(self, file_name):
        self.root = tk.Tk()
        self.root.title("Entries")
        self.file_name = file_name

        self.listbox = tk.Listbox(self.root)
        self.listbox.pack(pady=10)

        self.load_entries()

        self.add_button = tk.Button(self.root, text="Add Entry", command=self.add_entry)
        self.add_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.edit_button = tk.Button(self.root, text="Edit Entry", command=self.edit_entry)
        self.edit_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.remove_button = tk.Button(self.root, text="Remove Entry", command=self.remove_entry)
        self.remove_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.view_button = tk.Button(self.root, text="View Entry", command=self.view_entry)
        self.view_button.pack(side=tk.LEFT, padx=10, pady=10)

        self.root.mainloop()

    def load_entries(self):
        self.listbox.delete(0, tk.END)
        with open(self.file_name, "r") as pass_file:
            data = json.load(pass_file)
            for entry in data["entries"]:
                self.listbox.insert(tk.END, entry["name"])

    def add_entry(self):
        name = simpledialog.askstring("Add Entry", "Enter entry name:")
        user = simpledialog.askstring("Add Entry", "Enter user:")
        password = simpledialog.askstring("Add Entry", "Enter password:")

        if add_entry(self.file_name, name, user, password):
            self.load_entries()
        else:
            messagebox.showerror("Error", "Error adding entry")

    def edit_entry(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No entry selected")
            return

        name = self.listbox.get(selection[0])
        user = simpledialog.askstring("Edit Entry", "Enter new user:")
        password = simpledialog.askstring("Edit Entry", "Enter new password:")

        if edit_entry(self.file_name, name, user, password):
            self.load_entries()
        else:
            messagebox.showerror("Error", "Error editing entry")

    def remove_entry(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No entry selected")
            return

        name = self.listbox.get(selection[0])
        if remove_entry(self.file_name, name):
            self.load_entries()
        else:
            messagebox.showerror("Error", "Error removing entry")

    def view_entry(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "No entry selected")
            return

        name = self.listbox.get(selection[0])
        with open(self.file_name, "r") as pass_file:
            data = json.load(pass_file)
            for entry in data["entries"]:
                if entry["name"] == name:
                    EntryViewWindow(entry)
                    break


class EntryViewWindow:
    def __init__(self, entry):
        self.root = tk.Tk()
        self.root.title("Entry View")

        self.name_label = tk.Label(self.root, text=f"Name: {entry['name']}")
        self.name_label.pack(pady=10)

        self.user_label = tk.Label(self.root, text=f"User: {entry['user']}")
        self.user_label.pack(pady=10)

        self.password_label = tk.Label(self.root, text=f"Password: {entry['password']}")
        self.password_label.pack(pady=10)

        self.root.mainloop()


def main():
    parser = argparse.ArgumentParser(description='Manage password files.')

    parser.add_argument('-i', '--interactive', action='store_true', help='Interactive mode')
    parser.add_argument('-g', '--gui', action='store_true', help='GUI mode')

    parser.add_argument('-n', '--new', nargs=2, metavar=('FILE', 'PASSWORD'), help='Create new .pass file')
    parser.add_argument('-a', '--add', nargs=4, metavar=('FILE', 'NAME', 'USER', 'PASSWORD'), help='Add entry')
    parser.add_argument('-e', '--edit', nargs=4, metavar=('FILE', 'NAME', 'USER', 'PASSWORD'), help='Edit entry')
    parser.add_argument('-r', '--remove', nargs=2, metavar=('FILE', 'NAME'), help='Remove entry')
    parser.add_argument('-l', '--list', nargs=1, metavar='FILE', help='List entries')

    args = parser.parse_args()

    if args.gui:
        file_name = simpledialog.askstring("File", "Enter the name of the existing .pass file (with .pass extension):")
        if check_file_type(file_name):
            root = tk.Tk()
            AuthenticationWindow(root, file_name)
            root.mainloop()
        else:
            messagebox.showerror("Error", "Invalid file type or file does not exist.")
    elif args.interactive:
        interactive_main()
    else:
        arguments_main(args, parser)


if __name__ == "__main__":
    main()
