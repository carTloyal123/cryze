import asyncio
import websockets

async def send_hello():
    async with websockets.connect('ws://host.docker.internal:3033') as websocket:
        await websocket.send('Hello, World!')
        print("Message sent!")

asyncio.get_event_loop().run_until_complete(send_hello())
