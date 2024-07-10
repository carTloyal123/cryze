import os
import cv2
import asyncio
import websockets
import numpy as np
import json

# WebSocket URL
websocket_url = "ws://localhost:3030"

# OpenCV window name
window_name = "Decoded Frames"

# Named pipe for H264 data
h264_pipe = "local_pipe"

# Function to handle WebSocket messages
async def on_message(message):
    # Write H264 data to the pipe
    with open(h264_pipe, 'wb+') as f:
        f.write(message)

    # Decode H264 data into frames
    decoded_frame = decode_h264()
    if decoded_frame is None:
        print("Error decoding frame")
        return
    # Display the decoded frame using OpenCV
    cv2.imshow(window_name, decoded_frame)
    cv2.waitKey(1)

# Function to decode H264 data into frames
def decode_h264():
    cap = cv2.VideoCapture(h264_pipe)

    ret, frame = cap.read()

    if not ret:
        print("Error reading frame from pipe")
        return None

    return frame

# Function to start a WebSocket connection
async def start_websocket():
    async with websockets.connect(websocket_url) as ws:
        # Subscribe to the video stream
        await ws.send(json.dumps({"type": "Subscribe", "topic": "video-stream"}))

        async for message in ws:
            print("Received message of length " + str(len(message)))
            if isinstance(message, bytes):
                # Handle H264 data
                await on_message(message)
            else:
                # Handle control messages
                data = json.loads(message)
                print(data["message"])

# Start the WebSocket connection
asyncio.get_event_loop().run_until_complete(start_websocket())