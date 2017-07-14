import time

import bthomeclient

client = bthomeclient.BtHomeClient()

for i in range(100):
    time.sleep(1)
    print(client.get_devices())
