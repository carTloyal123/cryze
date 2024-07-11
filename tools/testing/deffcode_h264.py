import os
import cv2
import asyncio
import websockets
import numpy as np
import json
import deffcode

# WebSocket URL
websocket_url = "ws://localhost:3030"

# OpenCV window name
window_name = "Decoded Frames"

# Named pipe for H264 data
h264_pipe = "local_pipe.h264"

# Function to handle WebSocket messages
async def on_message(message):
    # Write H264 data to the pipe
    with open(h264_pipe, 'ab+') as f:
        f.write(message)

    print("Decoding H264 data!")
    try:
        # initialize and formulate the decoder for GRAYSCALE output
        decoder = deffcode.FFdecoder(h264_pipe, source_demuxer="yuv4mpegpipe", frame_format="yuv420p", verbose=True).formulate()

        print("Generating frames!")
        # grab the GRAYSCALE frames from the decoder
        for gray in decoder.generateFrame():

            # check if frame is None
            if gray is None:
                break

            # {do something with the gray frame here}

            # Show output window
            cv2.imshow("Gray Output", gray)

            # check for 'q' key if pressed
            key = cv2.waitKey(1) & 0xFF
            if key == ord("q"):
                break
    except Exception as e:
        print("Error decoding frame: " + str(e))
        return

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
    ffmpeg_path = deffcode.ffhelper.get_valid_ffmpeg_path(is_windows=True)
    if ffmpeg_path == False:
        print("FFmpeg not found in the system!")
        return
    print("FFmpeg path: " + ffmpeg_path)
    supported_demuxers = deffcode.ffhelper.get_supported_demuxers(ffmpeg_path)
    print("Supported demuxers: " + str(supported_demuxers))
    async with websockets.connect(websocket_url) as ws:
        # Subscribe to the video stream
        await ws.send(json.dumps({"type": "Subscribe", "topic": "video-stream"}))

        async for message in ws:
            print("Received message of length " + str(len(message)))
            if isinstance(message, bytes):
                # Handle H264 data
                print("Handling binary message!")
                await on_message(message)
            else:
                # Handle control messages
                data = json.loads(message)
                print(data["message"])

# Start the WebSocket connection
asyncio.get_event_loop().run_until_complete(start_websocket())