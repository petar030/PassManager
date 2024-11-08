import argparse
import sys
from core import *

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
        sys.exit(1)
def authenticate(file_name):
    try:
        with open(file_name, "r") as pass_file:
            data = json.load(pass_file)
            if "metadata" in data and "salt" in data["metadata"] and "hash" in data["metadata"]:
                salt = bytes.fromhex(data["metadata"]["salt"])
                hashed_password = bytes.fromhex(data["metadata"]["hash"])
                for i in range(0, 3):
                    password = input("Enter the password for the file: ")
                    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                        print("Password correct. Authentication successful.")
                        return True
                    elif i == 2:
                        print("Password incorrect. Authentication unsuccessful")
                        return False
                    else:
                        print("Incorrect password. Please try again.")
            else:
                print("Invalid file format.")
                return False
    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False
def main():
    parser = argparse.ArgumentParser(description="PassManager is a command-line tool for managing password files.")
    parser.add_argument("--interactive", action="store_true", help="Run PassManager in interactive mode.")
    parser.add_argument("--new", nargs=1, metavar=("file_name, password"), help="Make new .pass file (filename without .pass)")
    parser.add_argument("--add", nargs=4, metavar=("file_name", "name", "user", "password"), help="Add a new entry to a password file.")
    parser.add_argument("--edit", nargs=4, metavar=("file_name", "name", "user", "password"), help="Edit an existing entry in a password file.")
    parser.add_argument("--remove", nargs=2, metavar=("file_name", "name"), help="Remove an entry from a password file.")
    parser.add_argument("--list", nargs=1, metavar=("file_name"), help="List all entries in a password file.")
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()



    if args.interactive:
        interactive_main()
    else:
        arguments_main(args, parser)
if __name__ == "__main__":
    main()
