import time
import os
import csv
from openpyxl import load_workbook
from datetime import datetime
from scapy.all import ARP, Ether, srp
from manuf import manuf
import pandas as pd

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

def update_device_log(devices, device_log):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for device in devices:
        if device['mac'] not in device_log:
            device_log[device['mac']] = {
                'ip': device['ip'],
                'mac': device['mac'],
                'vendor': device['vendor'],
                'first_seen': current_time,
                'last_seen': current_time
            }
        else:
            device_log[device['mac']]['last_seen'] = current_time
    return device_log

def log_devices(device_log):
    file_path = "/home/ali/Documents/DeviceList.csv"
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        for mac, device in device_log.items():
            if mac in df['mac'].values:
                df.loc[df['mac'] == mac, 'last_seen'] = device['last_seen']
            else:
                new_row = pd.DataFrame([device])
                df = pd.concat([df, new_row], ignore_index=True)
        df.to_csv(file_path, index=False)
    else:
        df = pd.DataFrame(device_log.values())
        df.to_csv(file_path, index=False)

device_log = {}
while True:
    devices = arpscan()
    device_log = update_device_log(devices, device_log)
    log_devices(device_log)
    time.sleep(60)
