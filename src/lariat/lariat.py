#!/usr/bin/env python3

import argparse
import io
import ipaddress
import json
import logging
import os
import re
import sys
import typing
from pathlib import Path

import urllib3
from adb_shell.adb_device import AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from bravado.client import SwaggerClient
from bravado.exception import HTTPError
from bravado.requests_client import RequestsClient

logging.basicConfig(level=logging.INFO)

# Ignore cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EXIT_CODE_TOKEN = "exit_code:"
DEVICE_PUSH_DIR = "/data/local/tmp/"
CHMOD_755 = "chmod 755 %s"
# Workaround for getting exit code from adb_shell
# https://github.com/JeffLIrion/adb_shell/issues/217
ECHO_EXIT_CODE = " ; echo " + EXIT_CODE_TOKEN + "$?"
# Locked device will be automatically removed from the user control
# if it is kept idle for this period (in milliseconds);
LOCK_TIMEOUT_MS = 5000000
DEFAULT_ADB_PRI_KEY = Path.home() / ".android/adbkey"
DEFAULT_CFG_FILE = Path.home() / ".lariat/config.json"


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the DeviceFarmer automation tool.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(description="DeviceFarmer automation tool")

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-g",
        "--get-devices",
        action="store_true",
        help="Enumerate devices on DeviceFarmer instance. Does not execute any commands on devices. Prints JSON results to stdout.",
    )

    group.add_argument(
        "-e",
        "--exec-file",
        type=Path,
        help=f"Push a file and execute it. Pushes to {DEVICE_PUSH_DIR}.",
    )

    group.add_argument("-c", "--command", type=str, help="Run a command.")

    parser.add_argument(
        "--config",
        type=Path,
        default=Path(DEFAULT_CFG_FILE),
        help="Override the default path to the configuration file. Default:"
        + str(DEFAULT_CFG_FILE),
    )
    parser.add_argument(
        "-s",
        "--select",
        type=str,
        default=None,
        nargs="+",
        help="Select the fields to be returned by --get-devices (-g). If not specified, all fields are returned.",
    )

    parser.add_argument(
        "-f",
        "--filter",
        type=str,
        default=None,
        nargs="+",
        help="Filter devices via a list of key-value pairs (e.g., sdk=27 manufacturer=SAMSUNG). Non boolean values are regex matched",
    )

    parser.add_argument(
        "-p",
        "--push-files",
        type=Path,
        help="Specify the path to the file or directory to be pushed to the device. Pushes to "
        + str(DEVICE_PUSH_DIR)
        + ".",
    )

    parsed_args = parser.parse_args()

    if not (
        parsed_args.get_devices
        or parsed_args.push_files
        or parsed_args.exec_file
        or parsed_args.command
    ):
        parser.error("Must specify a command")

    if parsed_args.select and not parsed_args.get_devices:
        parser.error("The -s/--select option can only be used with -g/--get-devices.")

    if parsed_args.push_files:
        if not parsed_args.push_files.expanduser().exists():
            parser.error(
                "--push-files argument does not exist: " + str(parsed_args.push_files)
            )

    if parsed_args.exec_file:
        if not parsed_args.exec_file.expanduser().exists():
            parser.error(
                "--exec-file argument does not exist: " + str(parsed_args.exec_file)
            )

    return parsed_args


def load_config(
    config_file: Path,
) -> typing.Optional[typing.Dict[typing.Any, typing.Any]]:
    """Load a JSON configuration file.

    Args:
        config_file (Path): The path to the JSON configuration file.

    Returns:
        dict: The loaded configuration as a dictionary.
    """

    cfg = None
    try:
        with open(config_file, "r", encoding="utf-8") as file:
            cfg = json.load(file)
    except FileNotFoundError:
        logging.error(
            "Config file '%s' not found. Use --config to specify if using a non-default config file",
            config_file,
        )
    except json.JSONDecodeError:
        logging.exception("Invalid JSON format in config file '%s'", config_file)
    return cfg


def api_connect(
    api_url: str, api_token: str
) -> typing.Tuple[SwaggerClient, typing.Dict]:
    """Connect to a DeviceFarmer instance using the provided Swagger spec URL and API token.

    Args:
        api_url (str): The URL of the Swagger spec for the DeviceFarmer instance.
        api_token (str): The API token for authentication.

    Returns:
        Tuple[SwaggerClient, Dict]: A tuple containing the Swagger client instance and the request options.

    """

    _, ext = os.path.splitext(api_url)

    # The user can provide either the base URL of their Device Farmer instance (e.g myorg.devicefarmer.com)
    # or a full path to their Swagger 2.0 spec file (e.g myorg.devicefarmer.com/custom/path/swagger.json)
    # If the base URL is provided, the standard path for the Swagger spec file is appended
    if ext == ".json" or ext == ".yaml":
        spec_url = api_url
    else:
        spec_url = api_url + "/api/v1/swagger.json"

    logging.debug("Connecting to DeviceFarmer instance: %s", api_url)
    http_client = RequestsClient(ssl_verify=False)
    headers = {"Authorization": "Bearer " + api_token}
    client = SwaggerClient.from_url(spec_url, http_client)
    header = {"headers": headers}
    return client, header


def get_devices(
    client: SwaggerClient,
    request_opts: typing.Dict,
    fields=typing.Optional[typing.List[str]],
) -> typing.List[typing.Dict[typing.Any, typing.Any]]:
    """Retrieve a list of devices from the DeviceFarmer API.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        fields: Optional comma-separated list of fields to include. Defaults to all.

    Returns:
        A list of dictionaries representing the available devices.
    """

    fields_str = None

    if fields is not None:
        try:
            fields_str = ",".join(fields)
        except TypeError:
            logging.exception("Failed to convert list of fields to string")
            return []

    try:
        devices = (
            client.devices.getDevices(_request_options=request_opts, fields=fields_str)
            .response()
            .result
        )
    except HTTPError:
        logging.exception("Failed to get device list")
        return []

    device_list = devices.get("devices", [])

    # Remove any empty dictionaries
    device_list = list(filter(None, device_list))

    return device_list


def lock_device(
    client: SwaggerClient, request_opts: typing.Dict, serial: str, timeout: int
) -> bool:
    """Attempt to lock a device for user's control.

    If the device is already in use or unavailable, this operation will fail.

    Args:
        client (SwaggerClient): An instance of SwaggerClient that provides interaction with the DeviceFarmer API.
        request_opts (typing.Dict): A dictionary containing any additional request options to be passed to the API call.
        serial (str): The serial number of the device that we attempt to lock.
        timeout (int): Device will be automatically removed from the user control if it is kept idle for this period (in milliseconds).

    Returns:
        bool: True if the device has been successfully locked; otherwise, False.
    """

    device_obj = {"serial": serial, "timeout": timeout}
    try:
        client.user.addUserDevice(
            _request_options=request_opts, device=device_obj
        ).response()
    except HTTPError:
        logging.warning("Failed to lock device")
        return False
    return True


def unlock_device(
    client: SwaggerClient, request_opts: typing.Dict, serial: str
) -> None:
    """Unlocks a previously locked device.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        serial: The serial number of the device to be unlocked.

    """
    logging.debug("Unlocking device %s", serial)
    try:
        client.user.deleteUserDeviceBySerial(
            _request_options=request_opts, serial=serial
        ).response()
    except HTTPError:
        logging.exception("Failed to unlock device")


def get_remote_url(
    client: SwaggerClient, request_opts: typing.Dict, serial: str
) -> str:
    """Retrieves the remote connection URL for a device.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        serial: The serial number of the device.

    Returns:
        str: The remote connection URL of the device, or None if the device is not available.

    """
    resp = (
        client.user.remoteConnectUserDeviceBySerial(
            _request_options=request_opts, serial=serial
        )
        .response()
        .result
    )

    logging.debug("Remote connect URL %s", resp["remoteConnectUrl"])
    return resp["remoteConnectUrl"]


def adb_connect_device(
    device_url: str, signer: PythonRSASigner
) -> typing.Optional[AdbDeviceTcp]:
    """Connects to an ADB device over TCP/IP.

    Args:
        url: The URL specifying the IP address and port of the device.
        signer: An instance of PythonRSASigner representing the ADB signer.

    Returns:
        AdbDeviceTcp or None: An instance of AdbDeviceTcp if the connection is successful, or None otherwise.

    """
    try:
        ip_addr, port_str = device_url.split(":")
    except ValueError:
        logging.exception("invalid device url: %r", device_url)
        return None

    port = int(port_str)

    # Validate IP addr
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        logging.exception("Invalid ip address for device %r", ip_addr)
        return None

    # Validate port
    if not 1 <= port <= 65535:
        logging.error("Invalid port number for adb device: %r", port)
        return None

    try:
        device = AdbDeviceTcp(ip_addr, port, default_transport_timeout_s=60)
        device.connect(rsa_keys=[signer], auth_timeout_s=1)
    except Exception:
        logging.exception("Failed to connect to adb device %s", device_url)
        return None

    logging.debug("Connected to device %s", device_url)

    return device


def push_and_exec_file(device: AdbDeviceTcp, bin_path: Path) -> str:
    """Executes a file on the device.

    Args:
        device: An instance of AdbDeviceTcp representing the connected device.
        bin_path: The path to the file to be executed.

    Returns:
        str or None: The output of the executed file, or empty string if execution fails.

    """
    binary_file = os.path.basename(bin_path)

    try:
        device.push(bin_path.expanduser(), DEVICE_PUSH_DIR + binary_file)
    except Exception:
        logging.exception("Failed to push file")
        return ""

    try:
        device.shell(CHMOD_755 % (DEVICE_PUSH_DIR + binary_file))
    except Exception:
        logging.exception("Failed to set file permissions")
        return ""

    try:
        cmd_result = device.shell(
            DEVICE_PUSH_DIR + binary_file + ECHO_EXIT_CODE, read_timeout_s=60
        )
    except Exception:
        logging.exception("Failed to exec file")
        return ""

    return str(cmd_result)


def push_files(device: AdbDeviceTcp, filepath: Path) -> bool:
    """Pushes files to the device.

    Args:
        device: An instance of AdbDeviceTcp representing the connected device.
        filepath: The path to the file or directory to be pushed.

    Returns:
        bool: True if the files are successfully pushed, False otherwise.

    """
    push_abs_path = os.path.abspath(filepath.expanduser())
    file_list = []
    if not os.path.isdir(push_abs_path):
        file_list.append(push_abs_path)
    else:
        for file in os.listdir(push_abs_path):
            file_list.append(os.path.join(push_abs_path, file))
    for file in file_list:
        try:
            device.push(
                local_path=file, device_path=DEVICE_PUSH_DIR + os.path.basename(file)
            )
        except Exception:
            logging.exception("Failed to push files at path %s to device", filepath)
            return False

    return True


def build_unavailable(reason: str) -> typing.Dict[str, typing.Any]:
    """Build result for unavailable device.

    Args:
        reason: The reason why the device is unavailable.

    Returns:
        dict: A dictionary representing the unavailable status of the device.

    """
    result_dict = {}  # type: typing.Dict[str, typing.Any]
    result_dict["reason"] = reason
    return result_dict


def nested_get(dct: dict, key: str, default: typing.Any = None) -> typing.Any:
    """Retrieves nested dictionary values by dotted key name.

    Args:
        dct: dict to lookup key in.
        key: str key to look up.
        default: Default value to use if key is not found.

    Returns:
        value associated with key (of any type)

    """
    key_split = key.split(".", 1)
    val = dct.get(key_split[0], default)
    if isinstance(val, dict) and len(key_split) > 1:
        val = nested_get(val, key_split[1], default)
    return val


def filter_devices(
    device_list: typing.List[typing.Dict[typing.Any, typing.Any]],
    criteria: typing.Dict[str, typing.Any],
) -> typing.List[typing.Dict[str, typing.Any]]:
    """Filter a list of devices based on specified criteria.

    Args:
        device_list (List[str]): A list of DeviceFarmer devices in JSON format.
        criteria (Dict[str, Any]): Criteria dictionary of fields and values, where the values can contain regular expressions.

    Returns:
        List[str]: A list of devices in JSON format that match the filter criteria.

    Notes:
        - The values in the criteria JSON object can contain regular expressions
          for pattern matching.
        - Devices that do not match any of the specified filters will be removed
          from the result.
    """

    filtered_list = []
    # Convert bool strings to bool
    for key in criteria:
        if criteria[key].lower() == "true":
            criteria[key] = True  # type: ignore
        elif criteria[key].lower() == "false":
            criteria[key] = False  # type: ignore

    # Iterate all devices, and for each criteria, compare the value of the device key against the value of the criteria key
    # and add to the filtered list if they match
    for device in device_list:
        try:
            if all(
                (
                    (isinstance(nested_get(device, key), (int, str)))
                    and re.match(str(criteria[key]), str(nested_get(device, key)))
                )
                or criteria[key] == nested_get(device, key)
                for key in criteria
            ):
                filtered_list.append(device)
        except re.error as re_error:
            logging.error("Error in regular expression: %s", re_error.msg)
            return []

    return filtered_list


def result_to_dict(result_string: str) -> typing.Dict[str, typing.Any]:
    """Converts a result string to a dictionary representation.

    Extracts the exit code, if available, from the result string and constructs
    a dictionary with the following keys:

    - 'output': A string containing the output portion of the result_string.
    - 'exitcode': An integer representing the exit code extracted from the result_string.
                If no exit code is found, it will be set to None.

    Args:
        result_string (str): The result string to be converted to a dictionary.

    Returns:
        dict: A dictionary representing the result string with output and exitcode.

    """

    exitcode = None

    # Extract the return code from adb shell output
    res = io.StringIO(result_string)

    for line in res:
        if EXIT_CODE_TOKEN in line:
            try:
                exitcode = int(line.split(":")[1])
            except ValueError:
                logging.warning("Could not convert exit code to integer")
                exitcode = None

    result_output = {
        "output": result_string.split(EXIT_CODE_TOKEN, 1)[0].strip(),
        "exitcode": exitcode,
    }

    return result_output


def process_push_files(
    adb_device: AdbDeviceTcp, files: Path, stf_device: typing.Dict[str, typing.Any]
) -> typing.Dict[str, typing.Any]:
    """Process the pushing of files to a device.

    This function takes in an AdbDevice instance, the files to be pushed, and
    the dictionary of the device details, then it attempts to push the files to
    the device.

    Args:
        adb_device (AdbDevice): The AdbDevice instance representing the device.
        files (str): The files to be pushed to the device.
        stf_device (Dict[str, Any]): The dictionary containing details of the device.

    Returns:
        Dict[str, Any]: The result of the operation, containing 'output' and
        'exitcode' fields.
    """

    logging.info(
        "Pushing [%s] to device [%s %s %s]",
        files,
        stf_device.get("manufacturer"),
        stf_device.get("model"),
        stf_device.get("serial"),
    )
    if not push_files(adb_device, files):
        return build_unavailable("ADB failure pushing files")
    return {"output": "successfully pushed to device", "exitcode": 0}


def process_command(
    adb_device: AdbDeviceTcp, command: str, stf_device: typing.Dict[str, typing.Any]
) -> typing.Dict[str, typing.Any]:
    """Process the execution of a command on a device.

    This function takes in an AdbDevice instance, a command to be executed, and
    the dictionary of the device details, then it attempts to execute the
    command on the device.

    Args:
        adb_device (AdbDeviceTcp): The AdbDevice instance representing the device.
        command (str): The command to be executed on the device.
        stf_device (Dict[str, Any]): The dictionary containing details of the device.

    Returns:
        Dict[str, Any]: The result of the operation, containing 'output' and 'exitcode' fields.
    """

    logging.info(
        "Running command [%s] on device [%s %s (%s)]",
        command,
        stf_device.get("manufacturer"),
        stf_device.get("model"),
        stf_device.get("serial"),
    )
    try:
        result = adb_device.shell(command=command + ECHO_EXIT_CODE)
        return result_to_dict(str(result))
    except Exception as adb_exception:
        logging.warning("Failed to run shell command %s: %s", command, adb_exception)
        return build_unavailable("ADB failure running command")


def process_exec_file(
    adb_device: AdbDeviceTcp, exec_file: Path
) -> typing.Dict[str, typing.Any]:
    """Process the execution of a file on a device.

    This function takes in an AdbDevice instance and a file to be executed, then
    it attempts to execute the file on the device.

    Args:
        adb_device (AdbDeviceTcp): The AdbDevice instance representing the device.
        exec_file (str): The file to be executed on the device.

    Returns:
        Dict[str, Any]: The result of the operation, containing 'output' and
        'exitcode' fields.
    """

    result = push_and_exec_file(adb_device, exec_file)
    if not result:
        return build_unavailable("ADB failure executing file")

    return result_to_dict(result)


def check_device_availability(
    stf_device: typing.Dict[str, str]
) -> typing.Optional[str]:
    """
    Check if a device is available for use.

    Args:
        stf_device (dict): The device dictionary returned by the STF API.

    Returns:
        a string indicating the unavailability reason if the device is not available (otherwise None).
    """

    # Check if device is present
    # This typically refers to the physical availability of the device.
    # If a device is marked as 'present', it means that it is currently connected to the system.
    device_present = stf_device.get("present")
    if device_present is None:
        return "Unable to get 'present' field for device"
    if not device_present:
        return "Device is not present"

    # Check if device is ready
    # This usually signifies that the device is not only present, but also prepared for use.
    # It is switched on, booted up, and has no outstanding issues preventing it from functioning normally.
    device_ready = stf_device.get("ready")
    if device_ready is None:
        return "Unable to get 'ready' field for device"
    if not device_ready:
        return "Device is not ready"

    # Check if device is in use
    # If a device is 'using', it means that it is currently occupied and cannot be accessed by another user.
    device_in_use = stf_device.get("using")
    if device_in_use is None:
        return "Unable to get 'using' field for device"
    if device_in_use:
        return "Device is currently in use"

    return None


def process_device(
    stf_device: typing.Dict[str, str],
    swagger_client: SwaggerClient,
    request_options: typing.Dict[str, str],
    args: argparse.Namespace,
    key_signer: PythonRSASigner,
) -> typing.Tuple[str, typing.Dict[str, typing.Any]]:
    """Process a device based on the parsed command-line arguments.

    Depending on the arguments, the function may push files, execute a shell
    command, or execute a binary file.

    Args:
        stf_device (dict): The device dictionary returned by the STF API.
        swagger_client (SwaggerClient): The client to interact with the STF API.
        request_options (RequestOptions): The options for API requests.
        args (Namespace): Parsed command-line arguments.
        key_signer (PythonRSASigner): The signer for ADB authentication.

    Returns:
        tuple: A tuple comprising two elements - the device serial number, or
        `None` if the serial number was not retrievable, and a dictionary
        encapsulating the operation's outcome, or `None` if no operation was
        carried out.
    """

    device_result = {}

    device_serial = stf_device.get("serial")
    if device_serial is None:
        raise ValueError("No 'serial' key for stf device")

    unavailability_reason = check_device_availability(stf_device)
    if unavailability_reason is not None:
        return device_serial, build_unavailable(unavailability_reason)

    # Lock device
    locked = lock_device(
        swagger_client, request_options, device_serial, LOCK_TIMEOUT_MS
    )
    if locked:
        try:
            url = get_remote_url(swagger_client, request_options, device_serial)
            adb_device = adb_connect_device(url, key_signer)
            if adb_device is not None:
                if args.push_files:
                    device_result = process_push_files(
                        adb_device, args.push_files, stf_device
                    )
                if args.command:
                    device_result = process_command(
                        adb_device, args.command, stf_device
                    )
                elif args.exec_file:
                    logging.info(
                        "Executing binary [%s] on device [%r]",
                        args.exec_file,
                        device_serial,
                    )
                    device_result = process_exec_file(adb_device, args.exec_file)
            else:
                device_result = build_unavailable("Failed to connect via ADB")
        except Exception:
            logging.exception("Failed to process device")
        finally:
            unlock_device(swagger_client, request_options, device_serial)
    else:
        device_result = build_unavailable("Failed to lock device")

    return device_serial, device_result


def main() -> int:
    """Main entrypoint"""

    args = parse_args()

    config = load_config(config_file=args.config)
    if not config:
        return 1

    device_farmer_url = config.get("device_farmer_url")
    if not device_farmer_url:
        logging.error("Missing required config value 'device_farmer_url'")
        return 1

    access_token = config.get("access_token")
    if not access_token:
        logging.error("Missing required config value 'access_token'")
        return 1

    adb_private_key_path = config.get("adb_private_key_path", DEFAULT_ADB_PRI_KEY)

    try:
        swagger_client, request_options = api_connect(
            api_url=device_farmer_url, api_token=access_token
        )

    except Exception:
        logging.error(
            "Failed to connect to device farmer instance at %s", device_farmer_url
        )
        return 1

    filter_criteria = {}
    select_fields = set(args.select) if args.select else None
    if args.filter:
        try:
            # Convert list of strings to dict
            filter_criteria = dict(item.split("=") for item in args.filter)
        except ValueError:
            logging.exception("Invalid filter provided")
            return 1

        if select_fields is not None:
            select_fields.update(filter_criteria.keys())

    # Get all "available" devices on range
    stf_devices = get_devices(swagger_client, request_options, select_fields)
    # Filter devices if required
    if args.filter:
        stf_devices = filter_devices(stf_devices, filter_criteria)

    ## If get-devices, simply dump device info to stdout
    if args.get_devices:
        try:
            print(json.dumps(stf_devices, indent=4))
        except (TypeError, ValueError, OverflowError):
            logging.exception("Failed to serialize JSON")
            return 1
        return os.EX_OK

    try:
        key_signer = PythonRSASigner.FromRSAKeyPath(
            rsa_key_path=(os.path.abspath(adb_private_key_path))
        )
        # Use the key_signer object for authentication
    except (IOError, ValueError):
        logging.exception("Error reading RSA private key file")
        return 1

    results = {}

    for stf_device in stf_devices:
        device_serial, result = process_device(
            stf_device, swagger_client, request_options, args, key_signer
        )
        results[device_serial] = result

    try:
        results_json = json.dumps(results, indent=4)
    except (TypeError, ValueError, OverflowError):
        logging.exception("Failed to serialize JSON")
        return 1

    print(results_json)

    return os.EX_OK


if __name__ == "__main__":
    sys.exit(main())
