# Farmhand

Farmhand is a powerful command-line tool designed to streamline the execution of
commands and running of executables on remote Android devices. It achieves this
by leveraging [DeviceFarmer](https://github.com/DeviceFarmer/stf)'s API and the
Android Debug Bridge (ADB). With Farmhand, the cumbersome process of manually
connecting to devices, pushing files, running commands, and retrieving results
is simplified and made more efficient. It is an ideal solution for automating
tasks in continuous integration (CI) pipelines.

## Prerequisites

- Python 3.8 or higher
- ADB installed and added to the system's PATH
- DeviceFarmer [Access
  Token](https://github.com/DeviceFarmer/stf/blob/master/doc/API.md#authentication)
- JSON configuration file containing the Swagger spec URL and DeviceFarmer API
  token

## Installation

Farmhand is available on PyPI:

```sh
python -m pip install farmhand-util
```

Farmhand officially supports Python 3.8+.

## Configuration File

Farmhand utilizes a JSON configuration file. The default location for this
config file is in the `.farmhand` directory within the user's home directory
(`~/.farmhand/config.json`). The configuration file is used to specify the
following:

- `device_farmer_url`: The URL of the DeviceFarmer instance to connect to.
  - NOTE: Farmhand will append the standard API JSON spec to the base url. If
    using a custom path for your spec file, specify a full url ending in
    `.json` or `.yaml`.

- `access_token`: Your DeviceFarmer access token.
  - This can be obtained by logging into your DeviceFarmer UI, and going to
    Settings->Keys->Access Tokens

- `adb_private_key_path`: (Optional) Path to a non-default adb private key.
    Defaults to `~/.android/adbkey` if not specified

```json
{
   "access_token": "ef02da4fb3884395af4cf011061a2318ca5e9a04abd04de59c5c99afcce0b7fz",
   "device_farmer_url": "https://my.device-farmer-instance.com/",
   "adb_private_key_path": "/custom/path/adb.key"
}
```

## Usage

```sh
usage: farmhand [-h] [-g | -e EXEC_FILE | -c COMMAND] [--config CONFIG] [-s SELECT [SELECT ...]] [-f FILTER [FILTER ...]]
                [-p PUSH_FILES]

DeviceFarmer automation tool

optional arguments:
  -h, --help            show this help message and exit
  -g, --get-devices     Enumerate devices on DeviceFarmer instance. Does not execute any commands on devices. Prints JSON results
                        to stdout.
  -e EXEC_FILE, --exec-file EXEC_FILE
                        Push a file and execute it. Pushes to /data/local/tmp/.
  -c COMMAND, --command COMMAND
                        Run a command.
  --config CONFIG       Override the default path to the configuration file. Default:/home/larry.espenshade/.farmhand/config.json
  -s SELECT [SELECT ...], --select SELECT [SELECT ...]
                        Select the fields to be returned by --get-devices (-g). If not specified, all fields are returned.
  -f FILTER [FILTER ...], --filter FILTER [FILTER ...]
                        Filter devices via a list of key-value pairs (e.g., sdk=27 manufacturer=SAMSUNG). Non boolean values are
                        regex matched
  -p PUSH_FILES, --push-files PUSH_FILES
                        Specify the path to the file or directory to be pushed to the device. Pushes to /data/local/tmp/.
```

### Device Fields

The `--select` and `--filter` options both use "field names" to perform their
respective actions. These field names are JSON keys as defined by DeviceFarmer
as part of its REST API. You can view supported fields for your DeviceFarmer
installation by navigating to the following URL:
`https://<device_farmer_url>/api/v1/devices/<serial>` where `device_farmer_url`
is the URL to your DeviceFarmer installation and `serial` is the serial number
of one of your devices. The `/<serial>` component can be omitted to view all
fields of all devices.

Field names support dot notation to access nested keys. For example,
`battery.health` can be used to access the nested `health` key within `battery`.

Note that specifying a `--filter` along with a `--select` will automatically
include any field names specified in the filter in the resulting JSON.

#### Commonly Used Fields

- `abi` - Device Application Binary Interface (eg. `armeabi-v7a`)
- `manufacturer` - Device Manufacturer
- `marketName` - Device Marketing Name
- `model` - Device Model Name
- `provider.name` - STF Provider hosting this device
- `version` - Android version

### Examples

- Enumerate all devices on a DeviceFarmer instance:

```sh
farmhand --get-devices
```

- Limit the fields returned by `--get-devices`:

```sh
farmhand --get-devices --select serial model status
```

- Filter devices based on specific fields and values (e.g. all Samsung devices
  with SDK level 25-27):

```sh
farmhand --get-devices --filter manufacturer=SAMSUNG sdk=2[5-7]
```

- Filter devices based on JSON sub-key using dot notation:

```sh
farmhand --get-devices --filter provider.name=my.devicefarmer.com
```

- Push a local file to the device and execute it:

```sh
farmhand --exec-file path/to/hello
```

- Run a command on all arm64 devices:

```sh
farmhand --command "echo hello" --filter abi=arm64-v8a
```

- Push files to the device:

```sh
farmhand --push-files path/to/files
```

### Results

Farmhand returns results for each device that met the filtering criteria.

The following is sample output for an `echo` command:

```sh
farmhand --command "echo hello" --filter abi=arm64-v8a

"A12345": {
    "output": "hello",
    "exitcode": 0,
},
"B54321": {
    "output": "hello",
    "exitcode": 0,
},
"C678910": {
    "reason": "Device is currently in use",
}
```

Each result contains different fields depending on the device's availability:

- **If a device is unavailable**, the result will have a single field:
  - `reason`: Specifies why the device was not available for use, such as it being currently in use, not present on the range, etc.

- **If a device is available** and an operation was performed on it, the result will include two fields:
  - `output`: Contains the ADB shell output of the command executed, or details about the action performed.
  - `exitcode`: The return code of the command or action executed on the device.

Remember that a device will either have a 'reason' field (if it was unavailable) or 'output' and 'exitcode' fields

## Docker Image

For convenience, an official Farmhand Docker image is available.

To use the docker image, simply run

```sh
docker run --rm -v ~/.android:/root/.android:ro -v ~/.farmhand:/root/.farmhand:ro ghcr.io/zetier/farmhand:latest -c 'echo hello'
```

This docker run command creates and runs a Docker container based on the
ghcr.io/zetier/farmhand:latest image. It performs the following actions:

- Creates a read-only volume mount for the .android directory on the host
  machine, which contains ADB keys, to the /root/.android directory inside the
  container.

- Creates a read-only volume mount for the .farmhand directory on the host
  machine, which contains the farmhand configuration file, to the
  /root/.farmhand directory inside the container.

- The --rm flag ensures that the container is automatically removed after it
  exits.

- Inside the container, the command `farmhand -c 'echo hello'` is executed,
  which prints "hello" as the output on every lockable device on your
  DeviceFarmer range.

Please note that if your ADB keys and configuration file are located in
different directories on the host machine, you may need to modify the docker run
command accordingly to provide the correct paths for volume mounting.

## CI Integration

Farmhand was designed for simple integration into CI pipelines. Below is an
example of a GitLab job that tests a binary built in the pipeline on a
DeviceFarmer range:

```yml
.farmhand-test:
  image:
    name: ghcr.io/zetier/farmhand:latest
    entrypoint: [""]
  stage: test
  before_script:
    # Copy keys and configs from private CI variables
    - mkdir -p ~/.android
    - echo "$CI_ADB_PUB_KEY" > ~/.android/adbkey.pub
    - echo "$CI_ADB_PRI_KEY" > ~/.android/adbkey
    - echo "$CI_FARMHAND_CONFIG" -> ~/.farmhand/config.json
  script:
    - farmhand --file $BINARY > test_results.json
  artifacts:
    paths:
      - test_results.json

# Assumes a `build-android-binary` job that produces `android_binary`
# as an artifact.
android-range-test:
  extends: .farmhand-test
  variables:
    BINARY: android_binary
  needs:
    - build-android-binary

```

## Notes

- Farmhand will lock devices before performing any operations to ensure
  exclusive access. After the operations have been completed, the devices will
  be unlocked.

- Make sure to provide the correct path to the ADB private key file via
  `farmhand_config.json` if it is different from the default location
  (`~/.android/adbkey`)

- By default, Farmhand will enumerate ~every~ device on the DeviceFarmer range,
  including ones not `present` or `ready`. You can modify this as needed by
  specifying `--filter ready=true present=true` if needed.

## Development Install

NOTE: Farmhand is developed on and regularly tested with Ubuntu 18.04 with
Python 3.8. Other distributions and versions may work, but are currently
untested.

1. Clone the repository

2. Install dependencies along with the Farmhand python package

    ```sh
    sudo apt-get update
    sudo apt-get install python3-venv python3.8-venv -y
    python3.8 -m venv venv
    source venv/bin/activate
    (venv) pip install --upgrade pip
    (venv) pip install .
    ```

3. Create a [configuration file](#configuration-file)

## Contributing

Contributions are welcome! If you find any issues or have suggestions for
improvements, please open an issue or submit a pull request.

## License

This project is licensed under the GPLv2 License.
