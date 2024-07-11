import os
import requests
import websockets
import asyncio
import keyboard
import json
import time
import queue
import wyze_sdk
from wyze_sdk.service.base import WpkNetServiceClient
import wyze_sdk.errors

# p2pUrl = '|wyze-test-list.cloudlinks.cn|42.194.219.201'
# wyzeP2pUrl = '|wyze-mars-asrv.wyzecam.com'
# mars_url = 'https://wyze-mars-service.wyzecam.com/plugin/mars/v2/regist_gw_user/GW_BE1_7C78B2A2AD34'
mars_path_url = '/plugin/mars/v2/regist_gw_user/GW_BE1_7C78B2A2AD34'

wyze_sdk.set_file_logger('wyze_sdk', filepath='wyze_out.txt', level=wyze_sdk.logging.DEBUG)
mars_base_url = 'https://wyze-mars-service.wyzecam.com'
email = 'carsonloyal123@me.com'
psswd = 'YSHR*U*GVgn$*@u*@eT7EQ9e9r4w@bc5jGKdui&*^U84DW2o&Hcpitz@k$^F'
key_id = '8b47866c-fbf4-4cd4-894f-694836da9887'
api_key='AGzyRnvy4ysoicTwOlJxxNJgq9toGXEZaJDfor8k5rSvnGdUJjvkyncKV03r'
deviceId = "GW_BE1_7C78B2A2AD34"

last_token_fetch_time = 0
current_response = None

async def getLoginInfo():
    global last_token_fetch_time, current_response
    current_time = time.time()
    if current_time - last_token_fetch_time < 30 and current_response is not None:
        return current_response

    client = wyze_sdk.Client()
    response = client.login(
        email=email,
        password=psswd,
        key_id=key_id,
        api_key=api_key,
        totp_key='734700'
    )

    print(response.data)

    wpk = WpkNetServiceClient(token=client._token, base_url=mars_base_url)
    nonce = wpk.request_verifier.clock.nonce()
    json_dict = {"ttl_minutes" : 10080, 'nonce' : str(nonce), 'unique_id' : wpk.phone_id }
    header_dict = { 'appid' : wpk.app_id}

    try:
        resp = wpk.api_call(api_method=mars_path_url, json=json_dict, headers=header_dict, nonce=str(nonce))
        print("Got new login info!")
        last_token_fetch_time = time.time()
        current_response = resp
        return resp
    except requests.HTTPError as e:
        print(f'HTTP Request Error')
        print(e.response)
        print(str(e))
    except wyze_sdk.errors.WyzeApiError as e:
        print(f'Wyze API Error:')
        print(e.response)
    except wyze_sdk.errors.WyzeRequestError as e:
        print('Request error: ')
        print(e.args)

    return None



async def send_message(websocket):
    resp = await getLoginInfo()
    if resp is None:
        print("No login info")
        return
    accessId = resp["data"]["accessId"]
    accessToken = resp["data"]["accessToken"]
    expireTime = resp["data"]["expireTime"]

    print(accessId)
    print(accessToken)
    # Send a chat message
    chat_message = {
        "type": "login-info",
        "topic": "login-info",
        "data": {
            "accessId": "".join(accessId),
            "accessToken": accessToken,
            "expireTime": expireTime,
            "deviceId": deviceId,
            "timestamp": time.time()
        }
    }
    await websocket.send(json.dumps(chat_message))
    print("Sent message")

message_queue = queue.Queue()

def spacebar_event(e):
    message_queue.put("Your message")

async def subscribeToLoginInfo(websocket):
    chat_message = {
        "type": "Subscribe",
        "topic": "login-info"
    }
    await websocket.send(json.dumps(chat_message))

async def websocket_client():
    uri = "ws://localhost:3030"
    try:
        async with websockets.connect(uri, ping_timeout=None) as websocket:  # disable the library's automatic pinging
            websocket.ping_interval = None  # disable the library's automatic pinging
            keyboard.on_press_key('backslash', spacebar_event)
            await subscribeToLoginInfo(websocket)
            while True:
                try:
                    while not message_queue.empty():
                        message = message_queue.get()
                        await send_message(websocket)
                    await asyncio.sleep(1)
                except KeyboardInterrupt:
                    print("Ctrl+C pressed. Closing WebSocket connection...")
                    await websocket.close()
                    break
    except websockets.ConnectionClosedError as e:
        print(f"Connection closed: {e}")
    except websockets.InvalidStatusCode as e:
        print(f"Invalid status code: {e}")
    except websockets.InvalidURI as e:
        print(f"Invalid URI: {e}")
    except websockets.WebSocketProtocolError as e:
        print(f"WebSocket protocol error: {e}")
    except websockets.WebSocketException as e:
        print(f"WebSocket exception: {e}")
    except OSError as e:
        print(f"OS error: {e}")

if __name__ == "__main__":
    print("Starting websocket client")
    asyncio.get_event_loop().run_until_complete(websocket_client())
