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
                if len(message) < 1440*1440:
                    print("Message too short, skipping:" + str(len(message)))
                    continue
                
                print(message[:20])
                # Assume the message is a Y channel YUV420 image, convert it to a numpy array
                y = np.frombuffer(message, dtype=np.uint8)

                # Assume the image size is 480x640, reshape the numpy array to the correct dimensions
                y = y.reshape((1440, 1440))

                # Display the image
                cv2.imshow('Image', y)
                if cv2.waitKey(1) & 0xFF == ord('q'):  # Exit if Q is pressed
                    break
            else:
                # Handle control messages
                data = json.loads(message)
                print(data["message"])

# Start the event loop
asyncio.get_event_loop().run_until_complete(listen())
cv2.destroyAllWindows()