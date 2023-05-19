# FARMHAND

FARMHAND is a command-line tool that allows you to execute commands and run files on remote devices using DeviceFarmer's API and ADB. It simplifies the process of connecting to devices, pushing files, running commands, and retrieving results.

## Prerequisites

- Python 3.7 or higher
- ADB installed and added to the system's PATH
- DeviceFarmer API token
- JSON configuration file containing the Swagger spec URL and DeviceFarmer API token

## Installation

1. Clone the repository or download the script file.
2. Install the required dependencies by running the following command:

```sh
python3.8 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```sh
python farmhand.py --config <config_file> [options]
```

Replace <config_file> with the path to your JSON configuration file. The configuration file should contain the following keys:
- spec_url: The URL of the DeviceFarmer Swagger spec.
- token: Your DeviceFarmer API token.

```sh
Options
- -f, --file <file_path>: Path to the file to execute on the remote device.
- -c, --command <command>: Command to run on the remote device.
- -p, --push-files <file_or_directory>: Path to the file or directory to push to the remote device.
- --arm64: Run on 64-bit devices only.
- --adb-pri-key-file <key_file>: Path to the ADB private key file (default: ~/.android/adbkey).
```

### Examples

* Execute a file on a remote device:

```sh
   python farmhand.py --config config.json -f /path/to/file
```

* Run a command on multiple remote devices:

```sh
   python farmhand.py --config config.json -c "ls -l" --arm64
```

* Push files to multiple remote devices:

```sh
   python farmhand.py --config config.json -p /path/to/files --arm64
```

## Notes

- The FARMHAND tool will lock the devices before performing any operations to ensure exclusive access. After the operation is completed, the devices will be unlocked.
- Make sure to provide the correct path to the ADB private key file if it is different from the default location (~/.android/adbkey).

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the GPLv2 License.

