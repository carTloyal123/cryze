import asyncio
import websockets

async def send_hello():
    async with websockets.connect('ws://localhost:3030') as websocket:
        await websocket.send('Hello, World!')
        print("Message sent!")

asyncio.get_event_loop().run_until_complete(send_hello())