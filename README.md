# **PassManager**

## **Description**

PassManager is a command-line tool for managing encrypted password files. It provides functionalities to create, open, and modify .pass files, which securely store login credentials. The application supports both interactive and command-line interface (CLI) modes.

## **Features**

- **Interactive Mode**: Allows users to interact with the application through a text-based menu.
- **CLI Mode**: Users can perform operations directly through command-line arguments.
- **Encryption**: Ensures that the .pass files are encrypted and decrypted securely.
- **CRUD Operations**: Create, Read, Update, and Delete entries within the password file.

## **Installation**

To use PassManager, you need to have Python installed. Simply clone the repository and navigate to the directory.


```sh
git clone <repository-url>
```
cd passmanager

## **Usage**

### **Interactive Mode**

To run PassManager in interactive mode, use the following command:

```sh
python passmanager.py --interactive
```

In interactive mode, you can perform the following operations:

1. Create a new .pass file.
1. Open an existing .pass file and modify its contents.

### **Command-Line Mode**

PassManager supports several command-line arguments for different operations:

**Create a New File**

```sh
python passmanager.py --new <file\_name> <password>
```

- file\_name: Name of the new file (without .pass extension).
- password: Password for the new file.

**Open an Existing File**

```sh
python passmanager.py <file\_name>
```

- file\_name: Name of the existing .pass file (with .pass extension).

**Add a New Entry**

```sh
python passmanager.py --add <file\_name> <name> <user> <password>
```

- file\_name: Name of the existing .pass file.
- name: Name of the new entry.
- user: User for the new entry.
- password: Password for the new entry.

**Edit an Existing Entry**

```sh
python passmanager.py --edit <file\_name> <name> <user> <password>
```
- file\_name: Name of the existing .pass file.
- name: Name of the entry to edit.
- user: New user for the entry.
- password: New password for the entry.

**Remove an Entry**

```sh
python passmanager.py --remove <file\_name> <name>
```

- file\_name: Name of the existing .pass file.
- name: Name of the entry to remove.

**List All Entries**

```sh
python passmanager.py --list <file\_name>
```

- file\_name: Name of the existing .pass file.

## **Handling Interruptions**

PassManager handles keyboard interrupts (Ctrl+C) and termination signals to ensure that any pending encryption operations are completed before exiting.

## **Cleanup on Exit**

PassManager ensures that the .pass files are encrypted before the program exits, either through normal operation or due to an interrupt signal.

## **Development**

If you wish to contribute to PassManager, feel free to fork the repository and submit a pull request.

## **License**

PassManager is open-source software licensed under the MIT License. See the [LICENCE](./LICENCE.md)
 file for more details.

