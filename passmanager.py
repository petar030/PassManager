import argparse
import atexit
import signal
import sys
from core import *

class encryption_data:
    file_name = None
    password = None
    @classmethod
    def set_password(cls, password):
        cls.password = password
    @classmethod
    def get_password(cls):
        return cls.password
    @classmethod
    def set_file_name(cls, file_name):
        cls.file_name = file_name
    @classmethod
    def get_file_name(cls):
        return cls.file_name
    @classmethod
    def encrypt(cls):
        if cls.file_name is not None:
            encrypt(cls.file_name, cls.password)
            cls.file_name = None
            cls.password = None

def modify_existing_file(file_name):
    if not authenticate(file_name):
        return False
    while True:
        print("\nWhat do you want to do?")
        print("0. Go back")
        print("1. Add a new entry")
        print("2. Edit an existing entry")
        print("3. Remove an entry")
        print("4. List all entries")
        choice = input("Enter your choice (0-4): \n")
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
    encryption_data.encrypt()
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
            #TODO: check_password
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
        if list_entries(args.list[0]):
            pass
        else:
            print("Error listing entries.")
    else:
        argparser.print_help()
        encryption_data.encrypt()
        sys.exit(1)
    encryption_data.encrypt()
def authenticate(file_name):
    for i in range(3):
        password = input("Enter the password for the file: ")
        if authenticate_core(file_name, password):
            decrypt(file_name, password)
            encryption_data.set_file_name(file_name)
            encryption_data.set_password(password)
            return True
        elif i == 2:
            print("Password incorrect. Authentication unsuccessful")
            return False
        else:
            print("Incorrect password. Please try again.")


def main():
    parser = argparse.ArgumentParser(description="PassManager is a command-line tool for managing password files.")
    parser.add_argument("--interactive", action="store_true", help="Run PassManager in interactive mode.")
    parser.add_argument("--new", nargs=1, metavar=("file_name, password"),
                        help="Make new .pass file (filename without .pass)")
    parser.add_argument("--add", nargs=4, metavar=("file_name", "name", "user", "password"),
                        help="Add a new entry to a password file.")
    parser.add_argument("--edit", nargs=4, metavar=("file_name", "name", "user", "password"),
                        help="Edit an existing entry in a password file.")
    parser.add_argument("--remove", nargs=2, metavar=("file_name", "name"),
                        help="Remove an entry from a password file.")
    parser.add_argument("--list", nargs=1, metavar=("file_name"), help="List all entries in a password file.")
    parser.add_argument("file", nargs="?", help="Open specified .pass file")

    if len(sys.argv) < 1:
        parser.print_help()
        sys.exit(1)

    if len(sys.argv) == 1:
        sys.argv.append('--interactive')

    args = parser.parse_args()

    if args.interactive:
        interactive_main()
    elif args.file:
        if check_file_type(args.file):
            modify_existing_file(args.file)
        else:
            print("Invalid file type or file does not exist.")
    else:
        arguments_main(args, parser)


def cleanup():
    encryption_data.encrypt()

def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cleanup()
        sys.exit(0)
