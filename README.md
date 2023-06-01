# Farmhand

Farmhand is a command-line tool that allows you to execute commands and run
files on remote devices using DeviceFarmer's API and ADB. It simplifies the
process of connecting to devices, pushing files, running commands, and
retrieving results.

## Prerequisites

- Python 3.7 or higher
- ADB installed and added to the system's PATH
- DeviceFarmer API token
- JSON configuration file containing the Swagger spec URL and DeviceFarmer API
  token

## Installation

1. Clone the repository or download the script file.
2. Install the required dependencies by running the following command:

```sh
python3.8 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Create a [configuration file](#configuration-file)

### Configuration File

Farmhand utilizes a JSON configuration file. The default location for this
config file is in the user's home directory (~/.farmhand_config.json). The
configuration file is used to specify the following:
   - device_farmer_url: The URL of the DeviceFarmer instance.
     * NOTE: Farmhand will append the standard API JSON spec to the base url. If
       using a custom path for your spec file, specify a full url ending in
       .json or .yaml.
   - access_token: Your DeviceFarmer access token.
     * This can be obtained by logging into your DeviceFarmer UI, and going to
       Settings->Keys->Access Tokens
   - adb_private_key_path: (Optional) Path to non default adb private key.
     Defaults to ~/.android/adbkey if not specified

```json
{
   "access_token": "12345",
   "device_farmer_url": "https://my.device-farmer-instance.com/",
   "adb_private_key_path": "/custom/path/adb.key"
}
```

## Usage

```
usage: farmhand.py [-h] [-g | -e EXEC_FILE | -c COMMAND] [--config CONFIG] [-s SELECT [SELECT ...]] [-f FILTER_DEVICES [FILTER_DEVICES ...]] [-p PUSH_FILES]

DeviceFarmer automation tool

optional arguments:
  -h, --help            show this help message and exit
  -g, --get-devices     Enumerate devices on DeviceFarmer instance. Does not execute any commands on devices. Prints JSON results to stdout.
  -e EXEC_FILE, --exec-file EXEC_FILE
                        Push a file and execute it. Pushes to /data/local/tmp.
  -c COMMAND, --command COMMAND
                        Run a command.
  --config CONFIG       Override the default path to the configuration file. Default: ~/.farmhand_config.json.
  -s SELECT [SELECT ...], --select SELECT [SELECT ...]
                        Select the fields to be returned by --get-devices (-g). If not specified, all fields are returned.
  -f FILTER_DEVICES [FILTER_DEVICES ...], --filter-devices FILTER_DEVICES [FILTER_DEVICES ...]
                        Filter devices via a list of key-value pairs (e.g., key1=val1 key2=val2). Non boolean values are regex matched.
  -p PUSH_FILES, --push-files PUSH_FILES
                        Specify the path to the file or directory to be pushed to the device. Pushes to /data/local/tmp.
```

### Device Fields

The `--select` and `--filter-devices` options both use "field names" to perform
their respective actions. These field names are JSON keys as defined by
DeviceFarmer as part of its REST API. You can view supported fields for your
DeviceFarmer installation by navigating to the following URL:
"https://<device_farmer_url>/api/v1/devices/<serial>" where `device_farmer_url`
is the URL to your DeviceFarmer installation and `serial` is the serial number
of one of your devices. The `/<serial>` component can be dropped to view all
fields of all devices.

Field names support dot notation to access nested keys. For example,
`battery.health` can be used to access the nested `health` key within `battery`.

Note that specifying a `--filter` along with a `--select` will automatically
include any field names specified in the filter in the resulting JSON.

#### Commonly Used Fields

| Field Name | Description |
| ---------- | ----------- |
| abi | Device Application Binary Interface (eg. `armeabi-v7a`) |
| manufacturer | Device Manufacturer |
| marketName | Device Marketing Name |
| model | Device Model Name |
| provider.name | STF Provider hosting this device |
| version | Android version


### Examples

* Enumerate all devices on DeviceFarmer instance:

```sh
python farmhand.py --get-devices
```

* Limit the fields returned by `--get-devices`:

```sh
python farmhand.py --get-devices --select serial model status
```

* Filter devices based on specific fields and values (All Samsung SDK level
  25-27):

```sh
python farmhand.py --get-devices --filter-devices manufacturer=SAMSUNG sdk=2[5-7]
```

* Filter devices based on JSON sub-key using dot notation:

```sh
python farmhand.py --get-devices --filter-devices provider.name=my.devicefarmer.com
```

* Push a file to the device and execute it:

```sh
python farmhand.py --exec-file path/to/hello
```

* Run a command on all arm64 devices:

```sh
python farmhand.py --command "echo hello" --filter abi=arm64-v8a
```

* Push files to the device:

```sh
python farmhand.py --push-files path/to/files
```

### Results

Farmhand returns results for each device that an action was performed on.

The following is an example of sample output for the command

```sh
python farmhand.py --command "echo hello" --filter abi=arm64-v8a
```

```
    "A12345": {
        "output": "hello",
        "exitcode": 0,
        "available": true
    },
    "B54321": {
        "output": "hello",
        "exitcode": 0,
        "available": true
    },
    "C678910": {
        "available": false,
        "output": "Failed to lock device",
        "exitcode": null
    }
```

Each result contains the following fields:

* `available` -  Wether or not the device was available for this action.
* `output` - The resultant ADB shell output of the command _or_ details about
  action performed
* `exitcode` - return code of command or action. Null if no action performed.

Please note: An unavailable device can happen if a device is locked, or if it is
not present on DeviceFarmer at the time the operations were performed.

## Notes

- Farmhand will lock the devices before performing any operations to ensure
  exclusive access. After the operation is completed, the devices will be
  unlocked.
- Make sure to provide the correct path to the ADB private key file via
  `farmhand_config.json` if it is different from the default location
  (~/.android/adbkey)
- Farmhand is developed on and regularly tested under Ubuntu
- By default, Farmhand will enumerate ~every~ device on the DeviceFarmer range,
  including ones not `present` or `ready`. You can modify this as needed by
  specifying `--filter ready=true present=true` if needed.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for
improvements, please open an issue or submit a pull request.

## License

This project is licensed under the GPLv2 License.

