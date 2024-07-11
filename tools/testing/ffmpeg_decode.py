import os
import cv2
import asyncio
import websockets
import numpy as np
import json
import subprocess

# WebSocket URL
websocket_url = "ws://localhost:3030"

# OpenCV window name
window_name = "Decoded Frames"

# Named pipe for H264 data
h264_pipe = "local_pipe"

# Function to handle WebSocket messages
async def on_message(message):
    # Write H264 data to the pipe
    with open(h264_pipe, 'ab+') as f:
        print("writing to pipe")
        f.write(message)

    # process.stdin.write(message)
    # print("waiting for frame to return")
    # ret, decoded_frame = process.stdout.read()
    # if decoded_frame is not None:
    #     cv2.imshow('Video', decoded_frame)
    #     if cv2.waitKey(1) & 0xFF == ord('q'):
    #         return

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
# Set up the ffmpeg command with GPU acceleration
ffmpeg_command = [
    'C:\\ffmpeg\\bin\\ffmpeg.exe',
    '-i', 'pipe:0',
    '-f', 'rawvideo',
    '-pix_fmt', 'yuv420p',
    'pipe:1'
]

# Open the ffmpeg process
process = subprocess.Popen(ffmpeg_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
asyncio.get_event_loop().run_until_complete(start_websocket())