import asyncio
import websockets
import numpy as np
import random

async def send_random_YUV_data(uri, width, height):
    async with websockets.connect(uri, max_size=None) as websocket:
        # Define the frame size for YUV 4:2:0 format
        frame_size = width * height * 3 // 2
        print(f"Sending random YUV data with frame size {frame_size}")
        while True:
            try:
                # Generate random YUV data
                yuv_data = np.random.randint(0, 1, frame_size, dtype=np.uint8)

                # Send the binary data
                await websocket.send(yuv_data.tobytes())

                # Wait a random time before sending the next frame
                await asyncio.sleep(0.066)  # Random delay between 0.1 to 0.5 seconds
            except KeyboardInterrupt:
                print("Ctrl+C pressed. Closing WebSocket connection...")
                await websocket.close()

# Example usage
# Connect to the WebSocket server and send random YUV data with a specified resolution
# Replace 'ws://localhost:3030' with your WebSocket server URI and adjust the width and height as needed
asyncio.get_event_loop().run_until_complete(send_random_YUV_data('ws://localhost:3030', 240, 240))
