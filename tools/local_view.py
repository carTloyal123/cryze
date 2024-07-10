import os
import requests
import websockets
import asyncio
import json
import time
import queue
import wyze_sdk
from wyze_sdk.service.base import WpkNetServiceClient
import wyze_sdk.errors

## We need to get device credentials from the Wyze API for a desired device
## We are going to find all devices with the GW_BE1 device model prefix and take the first one
## Once we have a device, we can query Wyze for the P2P connection information
## Once we have the P2P connection information, we can send that info to the wyze server
## Server will hopefully send us back video frames
## Play video frames with opencv or similar

WYZE_EMAIL = os.environ['WYZE_EMAIL'] # Your Wyze email
WYZE_PASSWORD = os.environ['WYZE_PASSWORD'] # Your Wyze password
WYZE_KEY_ID = os.environ['WYZE_KEY_ID'] # Your Wyze key ID
WYZE_API_KEY = os.environ['WYZE_API_KEY']
