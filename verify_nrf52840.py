import sys
import os
import time
import serial
import serial.tools.list_ports

# Add necessary paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'boofuzz', 'utils', 'sweyntooth', 'libs'))

try:
    from boofuzz.utils.sweyntooth.drivers.NRF52_dongle import NRF52Dongle
    from colorama import Fore
except ImportError as e:
    print("Import error: {}".format(e))
    sys.exit(1)

def find_nrf_port():
    ports = serial.tools.list_ports.comports()
    print("Available ports:")
    for port in ports:
        print(" - {}: {} [{}]".format(port.device, port.description, port.hwid))
        if 'nRF52840' in port.description or 'Bluefruit' in port.description or 'J-Link' in port.description:
            return port.device
    return None

def main():
    port = find_nrf_port()
    if not port:
        print(Fore.RED + "Could not automatically find nRF52840 port. Please check connection.")
        # Try a common port if auto-detection fails but we want to be sure
        return

    print(Fore.GREEN + "Attempting to initialize NRF52Dongle on {}...".format(port))
    try:
        # Initialize the dongle
        dongle = NRF52Dongle(port_name=port, debug=True, logs=True)
        
        print(Fore.YELLOW + "Dongle initialized. Sending a test command (Set Log TX)...")
        # Sending a simple config command to see if it responds or crashes
        dongle.set_log_tx(1)
        
        print(Fore.GREEN + "Test command sent successfully.")
        
        # Wait a bit for any logs
        print("Waiting 2 seconds for any output from dongle...")
        start_time = time.time()
        while time.time() - start_time < 2:
            dongle.raw_receive()
            
        print(Fore.GREEN + "\nVerification complete. The device seems to be responding.")
        
    except Exception as e:
        print(Fore.RED + "Failed to communicate with the device: {}".format(e))
    finally:
        print("Closing script.")

if __name__ == "__main__":
    main()