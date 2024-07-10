import asyncio
import websockets
import os
import json

async def websocket_handler(uri):
    message_count = 0
    async with websockets.connect(uri) as websocket:
        await websocket.send(json.dumps({"type": "Subscribe", "topic": "video-stream"}))

        async for message in websocket:
            if isinstance(message, bytes):
                with open(f'frames/message_{message_count}.bin', 'wb') as f:
                    f.write(message)
                message_count += 1
                print(f"Message saved to message_{message_count}.bin")

# Replace with your WebSocket server URI
uri = "ws://localhost:3030"
asyncio.get_event_loop().run_until_complete(websocket_handler(uri))