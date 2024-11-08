import json
import os
import argparse
import sys

def make_file(file_name):
    new_file_name = file_name + ".pass"
    if os.path.isfile(new_file_name):
        print(f"File '{new_file_name}' already exists.")
        return None

    metadata = {"version": "1.0", "type": "pass"}
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
            for entry in data["entries"]:
                print(f"{i}: Name: {entry['name']}, User: {entry['user']}, Password: {entry['password']}")
                i += 1
            return True
    except Exception as e:
        print(f"Error reading file '{file_name}': {e}")
        return False

def modify_existing_file(file_name):
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
    print("Welcom to PassManager")
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
            file_name = make_file(file_name)
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
        file_name = make_file(args.new[0])
        if file_name is not None:
                print(f"File '{file_name}' created successfully.")
    elif args.add:
        if add_entry(args.add[0], args.add[1], args.add[2], args.add[3]):
            print("Entry added successfully.")
        else:
            print("Error adding entry.")
    elif args.edit:
        if edit_entry(args.edit[0], args.edit[1], args.edit[2], args.edit[3]):
            print("Entry edited successfully.")
        else:
            print("Error editing entry.")
    elif args.remove:
        if remove_entry(args.remove[0], args.remove[1]):
            print("Entry removed successfully.")
        else:
            print("Error removing entry.")
    elif args.list:
        if list_entries(args.list[0]):
            pass
        else:
            print("Error listing entries.")
    else:
        argparser.print_help()
        sys.exit(1)



def main():
    parser = argparse.ArgumentParser(description="PassManager is a command-line tool for managing password files.")
    parser.add_argument("--interactive", action="store_true", help="Run PassManager in interactive mode.")
    parser.add_argument("--new", nargs=1, metavar=("file_name"), help="Make new .pass file (filename without .pass)")
    parser.add_argument("--add", nargs=4, metavar=("file_name", "name", "user", "password"), help="Add a new entry to a password file.")
    parser.add_argument("--edit", nargs=4, metavar=("file_name", "name", "user", "password"), help="Edit an existing entry in a password file.")
    parser.add_argument("--remove", nargs=2, metavar=("file_name", "name"), help="Remove an entry from a password file.")
    parser.add_argument("--list", nargs=1, metavar=("file_name"), help="List all entries in a password file.")
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    #authenticate(file_name)
    #decrypt(file_name)

    if args.interactive:
        interactive_main()
    else:
        arguments_main(args, parser)



if __name__ == "__main__":
    main()
