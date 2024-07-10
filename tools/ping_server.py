import asyncio
import websockets
import json

async def ping_server():
    uri = "ws://localhost:3030"  # Replace with your server URI
    async with websockets.connect(uri) as websocket:
        while True:
            # Create a subscription message
            message = json.dumps({"type": "Subscribe", "topic": "example_topic"})
            await websocket.send(message)
            
            # Wait for an acknowledgment message from the server
            ack_message = await websocket.recv()
            print(f"Received: {ack_message}")
            
            # Wait for 1 second before sending the next message
            await asyncio.sleep(1)

asyncio.get_event_loop().run_until_complete(ping_server())