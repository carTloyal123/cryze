import asyncio
import websockets
import numpy as np
import cv2
import json

async def listen():
    uri = "ws://localhost:3030"  # replace with your WebSocket server URI
    async with websockets.connect(uri, max_size=None) as websocket:
        await websocket.send(json.dumps({"type": "Subscribe", "topic": "video-stream"}))
        async for message in websocket:
            if isinstance(message, bytes):
                # print the first 100 characters of the message
                print(f"Received message with length {len(message)}")
                if len(message) < 1440*1440*3/2:  # Adjust this if your YUV format is different
                    print("Message too short, skipping:" + str(len(message)))
                    continue
                
                print(message[:20])
                y_size = 1440*1440
                uv_size = 518400
                # Assume the message is a YUV420 image, slice it into Y, U, and V channels
                y = np.frombuffer(message[:y_size], dtype=np.uint8).reshape((1440, 1440))
                u = np.frombuffer(message[y_size:y_size+uv_size], dtype=np.uint8).reshape((720, 720))
                v = np.frombuffer(message[y_size+uv_size:], dtype=np.uint8).reshape((720, 720))
                # Upsample U and V channels to match Y channel
                u_upsampled = cv2.resize(u, (1440, 1440))
                v_upsampled = cv2.resize(v, (1440, 1440))

                # Stack the Y, U, and V channels to create a YUV image
                yuv = cv2.merge([y, u_upsampled, v_upsampled])

                # Convert the YUV image to an RGB image
                rgb = cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR)

                # Display the image
                cv2.imshow('Image', rgb)
                if cv2.waitKey(1) & 0xFF == ord('q'):  # Exit if Q is pressed
                    break
            else:
                # Handle control messages
                data = json.loads(message)
                print(data["message"])

# Start the event loop
asyncio.get_event_loop().run_until_complete(listen())
cv2.destroyAllWindows()