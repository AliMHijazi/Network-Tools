# Network scanner based on arpscan. Saves all device IPs, MACs, and vendor names,
# and logs the time that they were first and last seen. Scans every 60 seconds.
# To do: 
# - Run in background
# - More info from scan?

import time
import os
import logging
import pandas as pd

from datetime import datetime
from scapy.all import ARP, Ether, srp
from manuf import manuf
from threading import Thread
from queue import Queue
from logging.handlers import RotatingFileHandler

# Log file setup - Change backupCount for amount of backup files, and maxBytes for max size.
log_formatter = logging.Formatter('%(asctime)s %(message)s')
dir_path = os.path.join(os.getcwd(), 'LogsAndDevices')
log_file = os.path.join(dir_path, 'networkScanner.log')

if not os.path.exists(dir_path):
    os.makedirs(dir_path)
    
log_handler = RotatingFileHandler(log_file, mode='a', maxBytes=5*1024*1024, backupCount=2, encoding=None, delay=0)
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)
logger = logging.getLogger('root')
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# Scans the local network. Change target_ip as needed
def arpscan():
    target_ip = "192.168.1.1/24"
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        mac = received.hwsrc
        vendor = manuf.MacParser().get_manuf(mac)
        devices.append({'ip': received.psrc, 'mac': mac, 'vendor': vendor})
    return devices
    
# Gets the name of the device through user input.
def get_device_name(device_mac, device_name_queue, device_vendor):
    device_name = input(f"New Device Detected\nWould you like to name the device with MAC address {device_mac[-5:]} from {device_vendor}?: ")
    logging.info(f"New Device Detected - Putting {device_name} with MAC address {device_mac} into queue")
    device_name_queue.put((device_mac, device_name))

# Update log based on the recently seen devices and time seen.
def update_device_log(devices, device_log, device_name_queue):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    connected_macs = [device['mac'] for device in devices]
    for mac in device_log:
        device_log[mac]['connected'] = 'Yes' if mac in connected_macs else 'No'

    # Read existing device names from CSV file
    file_path = os.path.join(dir_path, 'DeviceList.csv')
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        if 'mac' in df.columns:
            for index, row in df.iterrows():
                mac = row['mac']
                name = row['name']
                if mac in device_log:
                    device_log[mac]['name'] = name
    else:
        df = pd.DataFrame(columns=['ip', 'mac', 'vendor', 'first_seen', 'last_seen', 'connected', 'name'])
        df.to_csv(file_path, index=False)

    
    for device in devices:
        if device['mac'] not in device_log:
            # Check if the name is already present in the CSV file
            name_in_csv = ''
            if 'mac' in df.columns and df.loc[df['mac'] == device['mac'], 'name'].size > 0:
                name_in_csv = df.loc[df['mac'] == device['mac'], 'name'].values[0]
            # Start a new thread to get the device name only if the name is not already present in the CSV file or the device_log dictionary
            if not name_in_csv and not device_log.get(device['mac'], {}).get('name'):
                Thread(target=get_device_name, args=(device['mac'], device_name_queue, device['vendor'])).start()
            # Add the new device to the device_log dictionary with the name from the CSV file if it exists
            device_log[device['mac']] = {
                'ip': device['ip'],
                'mac': device['mac'],
                'vendor': device['vendor'],
                'first_seen': current_time,
                'last_seen': current_time,
                'connected': 'Yes',
                'name': name_in_csv
            }
        else:
            device_log[device['mac']]['last_seen'] = current_time
    while not device_name_queue.empty():
        mac, name = device_name_queue.get()
        logging.info(f"Got {name} from queue")
        if mac in device_log:
            device_log[mac]['name'] = name
    return device_log

# Open the csv file and log the device info
def log_devices(device_log):
    file_path = os.path.join(dir_path, 'DeviceList.csv')
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        for mac, device in device_log.items():
            if mac in df['mac'].values:
                df.loc[df['mac'] == mac, ['last_seen', 'connected', 'name']] = [device['last_seen'], device['connected'], device['name']]
            else:
                new_row = pd.DataFrame([device])
                df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv(file_path, index=False)
    else:
        df = pd.DataFrame(device_log.values())
        df.to_csv(file_path, index=False)
        
device_name_queue = Queue()
device_log = {}
print("Running...")
logging.info("Starting networkScanner.py")
while True:
    devices = arpscan()
    device_log = update_device_log(devices, device_log, device_name_queue)
    log_devices(device_log)
    time.sleep(30) # Edit the sleep time to change the scan rate

