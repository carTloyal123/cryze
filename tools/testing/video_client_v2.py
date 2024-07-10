import asyncio
import websockets
import cv2
import json
import numpy as np
import binascii

# Define the marker bytes for frame start
frame_start_marker = b'\x00\x00\x00\x00\x00\x00\x00'

# Variables to store incoming binary data and YUV frames
incoming_data = bytearray()
frame_in_progress = False

async def websocket_handler(uri):
    global incoming_data, frame_in_progress
    frame_count = 0
    async with websockets.connect(uri) as websocket:
        await websocket.send(json.dumps({"type": "Subscribe", "topic": "video-stream"}))
        async for message in websocket:
            if isinstance(message, bytes):
                # Process and display the YUV frame
                process_and_display_frame(message)
                frame_count += 1
            else:
                # Handle control messages
                data = json.loads(message)
                print(data["message"])

def process_and_display_frame(data):
    # Assuming that data contains YUV frame in binary format
    # Process the binary data to convert it to a frame and display it
    # Replace this with your actual YUV frame processing code
    # Here, we create a placeholder frame for demonstration purposes
    frame_width = 240
    frame_height = 240
    frame_size = frame_width * frame_height * 3 // 2  # YUV 4:2:0 format
    if len(data) < frame_size:
        print("Incomplete frame received")
        # The data received is not a complete frame
        # Store the data and wait for more data
        # pad the data with zeros
        data += b'\x00' * (frame_size - len(data))

    if len(data) > frame_size:
        print("Extra data received")
        # chop off end of data
        data = data[:frame_size] 

    print("Frame size: ", frame_size)
    print("Data length: ", len(data))
    frame_data = np.frombuffer(data, dtype=np.uint8).reshape((240 * 3 // 2, 240))
    frame = cv2.cvtColor(frame_data, cv2.COLOR_YUV2BGR_I420)
    
    cv2.imshow('YUV Frame', frame)
    cv2.waitKey(1)

if __name__ == "__main__":
    # Replace 'wss://your_websocket_server_uri' with your actual WebSocket server URI
    websocket_uri = 'ws://localhost:3030'
    
    asyncio.get_event_loop().run_until_complete(websocket_handler(websocket_uri))
    asyncio.get_event_loop().run_forever()
