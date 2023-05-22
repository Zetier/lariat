#!/usr/bin/env python3

import argparse
import os
import sys
import logging
import io
import json
import typing
from pathlib import Path
from pprint import pprint

import urllib3
from bravado.client import SwaggerClient
from bravado.requests_client import RequestsClient
from bravado.exception import HTTPClientError
from adb_shell.adb_device import AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner

logging.getLogger().setLevel((logging.INFO))

# TODO: Add certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EXIT_CODE = 'exit_code:'
ECHO_EXIT_CODE = ' ; echo ' + EXIT_CODE + '$?'
# Locked device will be automatically removed from the user control
# if it is kept idle for this period (in milliseconds);
TIMEOUT = 5000000
DEFAULT_ADB_PRI_KEY = Path.home() / '.android/adbkey'


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the STF automation script.

    Returns:
        argparse.Namespace: An object containing the parsed arguments.

    """
    parser = argparse.ArgumentParser(description='Farmhand')
    parser.add_argument(
        '--config',
        type=Path,
        default='config.json',
        help=
        'Override the default path to the JSON configuration file containing the Swagger spec URL and DeviceFarmer API token.'
    )
    parser.add_argument(
        '-f',
        '--file',
        type=Path,
        help='Specify the path to the file to be executed on the device.')
    parser.add_argument(
        '-c',
        '--command',
        type=str,
        help='Specify the command to be run on the device.')
    parser.add_argument(
        '-p',
        '--push-files',
        type=Path,
        help=
        'Specify the path to the file or directory to be pushed to the device. Pushes to /data/local/tmp.')
    parser.add_argument(
        '--arm64',
        action='store_true',
        default=False,
        help='Run on 64-bit devices only.')
    parser.add_argument(
        '--adb-pri-key-file',
        type=Path,
        default=DEFAULT_ADB_PRI_KEY,
        help='Override the default ADB private key file location.')

    return parser.parse_args()


def load_config(config_file: Path) -> typing.Dict:
    """
    Load a JSON configuration file.

    Args:
        config_file (Path): The path to the JSON configuration file.

    Returns:
        dict: The loaded configuration as a dictionary.
    """

    cfg = None
    try:
        with open(config_file, 'r', encoding='utf-8') as file:
            cfg = json.load(file)
    except FileNotFoundError:
        logging.error(
            "Config file '%s' not found. Use --config to specify if using a non-default config file",
            config_file)
    except json.JSONDecodeError:
        logging.error("Invalid JSON format in config file '%s'", config_file)
        sys.exit(1)
    return cfg


def api_connect(spec_url: str,
                token: str) -> typing.Tuple[SwaggerClient, typing.Dict]:
    """
    Connect to a DeviceFarmer instance using the provided Swagger spec URL and API token.

    Args:
        spec_url (str): The URL of the Swagger spec for the DeviceFarmer instance.
        token (str): The API token for authentication.

    Returns:
        Tuple[SwaggerClient, Dict]: A tuple containing the Swagger client instance and the request options.

    """

    logging.info("Connecting to DeviceFarmer instance: %s", spec_url)
    http_client = RequestsClient(ssl_verify=False)
    headers = {'Authorization': 'Bearer ' + token}
    client = SwaggerClient.from_url(spec_url, http_client)
    header = {'headers': headers}
    return client, header


def get_devices(client: SwaggerClient, request_opts: typing.Dict,
                arm64: bool) -> typing.Dict:
    """Retrieve a list of devices from the DeviceFarmer API.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        arm64: A boolean indicating whether to filter devices for 64-bit architecture.

    Returns:
        A list of dictionaries representing the available devices.
    """

    try:
        devices = client.devices.getDevices(
            _request_options=request_opts).response().result
    except HTTPClientError:
        logging.exception("failed to get device list")
        return None

    ready_devices = []

    for device in devices['devices']:
        if device['ready'] and device['present']:
            if arm64:
                if device['abi'] == "arm64-v8a":
                    ready_devices.append(device)
            else:
                ready_devices.append(device)
    return ready_devices


def lock_device(client: SwaggerClient, request_opts: typing.Dict,
                serial: str) -> bool:
    """Locks a device by adding it to the user's control.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        serial: The serial number of the device to be locked.

    Returns:
        bool: True if the device is successfully locked, False otherwise.

    """
    logging.debug("locking device")
    device_obj = {'serial': serial, 'timeout': TIMEOUT}
    logging.debug("locking device %s", serial)
    try:
        client.user.addUserDevice(
            _request_options=request_opts, device=device_obj).response()
    except HTTPClientError:
        logging.warning("Failed to lock device")
        return False
    return True


def unlock_device(client: SwaggerClient, request_opts: typing.Dict,
                  serial: str) -> None:
    """Unlocks a previously locked device.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        serial: The serial number of the device to be unlocked.

    """
    logging.debug("unlocking device %s", serial)
    try:
        client.user.deleteUserDeviceBySerial(
            _request_options=request_opts, serial=serial).response()
    except HTTPClientError:
        logging.exception("Failed to unlock device")


def get_remote_url(client: SwaggerClient, request_opts: typing.Dict,
                   serial: str) -> str:
    """Retrieves the remote connection URL for a device.

    Args:
        client: An instance of SwaggerClient representing the DeviceFarmer API client.
        request_opts: Additional request options to be passed to the API call.
        serial: The serial number of the device.

    Returns:
        str: The remote connection URL of the device, or None if the device is not available.

    """
    try:
        resp = client.user.remoteConnectUserDeviceBySerial(
            _request_options=request_opts, serial=serial).response().result
    except HTTPClientError as client_err:
        logging.warning("Device not available: %s", client_err)
        return None

    logging.debug("remote connect URL %s", resp['remoteConnectUrl'])
    return resp['remoteConnectUrl']


def adb_connect_device(spec_url: str, signer: PythonRSASigner
                      ) -> typing.Optional[AdbDeviceTcp]:
    """Connects to an ADB device over TCP/IP.

    Args:
        spec_url: The URL specifying the IP address and port of the device.
        signer: An instance of PythonRSASigner representing the ADB signer.

    Returns:
        AdbDeviceTcp or None: An instance of AdbDeviceTcp if the connection is successful, or None otherwise.

    """
    ip_addr, port = spec_url.split(':')
    try:
        device = AdbDeviceTcp(
            ip_addr, int(port), default_transport_timeout_s=60)
        device.connect(rsa_keys=[signer], auth_timeout_s=1)
        logging.debug("connected to device %s", url)
    except Exception:
        logging.exception("failed to connect to adb device %s", url)
        return None

    return device


def exec_file(device: AdbDeviceTcp, bin_path: str) -> typing.Optional[str]:
    """Executes a file on the device.

    Args:
        device: An instance of AdbDeviceTcp representing the connected device.
        bin_path: The path to the file to be executed.

    Returns:
        str or None: The output of the executed file, or None if execution fails.

    """
    device_dir = "/data/local/tmp/"
    binary_file = os.path.basename(bin_path)

    try:
        device.push(bin_path, device_dir + binary_file)
    except Exception:
        logging.exception("failed to push file")
        return None

    try:
        device.shell("chmod 755 " + device_dir + binary_file)
    except Exception:
        logging.exception("failed to execute file")
        return None

    return device.shell(
        device_dir + binary_file + ECHO_EXIT_CODE, read_timeout_s=60)


def push_files(device: AdbDeviceTcp, filepath: str) -> bool:
    """Pushes files to the device.

    Args:
        device: An instance of AdbDeviceTcp representing the connected device.
        filepath: The path to the file or directory to be pushed.

    Returns:
        bool: True if the files are successfully pushed, False otherwise.

    """
    try:
        push_abs_path = os.path.abspath(filepath)
        file_list = []
        if not os.path.isdir(push_abs_path):
            file_list.append(push_abs_path)
        else:
            for file in os.listdir(push_abs_path):
                file_list.append(os.path.join(push_abs_path, file))
        for file in file_list:
            logging.info("pushing [%s] to device [%s]", file,
                         stf_device['serial'])
            device.push(file, "/data/local/tmp/" + os.path.basename(file))
        return True

    except Exception:
        logging.exception("failed to push files at path %s to device: %s",
                          filepath, device['serial'])
        return False


def build_unavailable(reason: str) -> typing.Dict:
    """
    Build result for unavailable device.

    Args:
        reason: The reason why the device is unavailable.

    Returns:
        dict: A dictionary representing the unavailable status of the device.

    """
    result_dict = {}
    result_dict['available'] = False
    result_dict['output'] = reason
    result_dict['exitcode'] = None
    return result_dict


if __name__ == '__main__':

    args = parse_args()
    config = load_config(config_file=args.config)
    if not config:
        sys.exit(1)
    try:
        swagger_client, request_options = api_connect(
            spec_url=config['spec_url'], token=config['token'])

    except Exception as e:
        logging.error("Failed to connect to spec url %s: %s",
                      config['spec_url'], e)
        sys.exit(1)

    try:
        key_signer = PythonRSASigner.FromRSAKeyPath(
            rsa_key_path=str(args.adb_pri_key_file.resolve()))
        # Use the key_signer object for authentication
    except IOError as e:
        logging.error("Error reading RSA private key file: %s", e)
    except ValueError as e:
        logging.error("Invalid RSA private key file: %s", e)

    stf_devices = get_devices(swagger_client, request_options, args.arm64)

    results = {}
    for stf_device in stf_devices:
        if not lock_device(swagger_client, request_options,
                           stf_device['serial']):
            results[stf_device['serial']] = build_unavailable(
                "failed to lock device")
            continue

        url = get_remote_url(swagger_client, request_options,
                             stf_device['serial'])
        if url is None:
            unlock_device(swagger_client, request_options, stf_device['serial'])
            results[stf_device['serial']] = build_unavailable(
                "failed to get remote url")
            continue










        adb_device = adb_connect_device(url, key_signer)
        if adb_device is None:
            unlock_device(swagger_client, request_options, stf_device['serial'])
            results[stf_device['serial']] = build_unavailable(
                "failed to connect via ADB")
            continue

        if args.push_files:
            if not push_files(adb_device, args.push_files):
                unlock_device(swagger_client, request_options,
                              stf_device['serial'])
                results[stf_device['serial']] = build_unavailable(
                    "ADB failure pushing files")
                continue
            result = 'successfully pushed to device'
            exitcode = 0

        if args.command:
            logging.info("running command [%s] on device [%s]", args.command,
                         stf_device['serial'])
            try:
                result = adb_device.shell(command=args.command + ECHO_EXIT_CODE)
            except Exception as e:
                logging.error("failed to run shell command %s: %s",
                              args.command, e)
                unlock_device(swagger_client, request_options,
                              stf_device['serial'])
                results[stf_device['serial']] = build_unavailable(
                    "ADB failure running command")
                continue

        elif args.file:
            logging.info("executing binary [%s] on device [%s]", args.file,
                         stf_device['serial'])
            result = exec_file(adb_device, args.file)
            if result is None:
                unlock_device(swagger_client, request_options,
                              stf_device['serial'])
                results[stf_device['serial']] = build_unavailable(
                    "ADB failure executing file")
                continue

        logging.debug("Result: %r", result)

        # Extract the return code from adb shell output
        s = io.StringIO(result)

        for line in s:
            if EXIT_CODE in line:
                exitcode = int(line.split(':')[1])

        result_output = {
            'output': result.split(EXIT_CODE, 1)[0].strip(),
            'exitcode': exitcode,
            'available': True
        }

        results[stf_device['serial']] = result_output
        unlock_device(swagger_client, request_options, stf_device['serial'])

    logging.info("finished processing on all devices")
    pprint(results)

    sys.exit(0)
