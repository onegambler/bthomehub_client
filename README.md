# Home Hub Client

A Python client that can interact with BT Home Hub routers.

At present, only device listing has been implemented: it returns a list of all connected devices.
## Usage

```python
import bthomeclient

client = bthomeclient.BtHomeClient()

client.authenticate()

print(client.get_devices())
```