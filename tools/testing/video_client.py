import asyncio
import websockets
import json
import cv2
import numpy as np

async def video_client():
    uri = "ws://localhost:3030"
    async with websockets.connect(uri, max_size=None) as websocket:
        await websocket.send(json.dumps({"type": "Subscribe", "topic": "video-stream"}))
        frame_buffer = bytearray()
        frame_delimiter = b'\x00\x00\x00\x00\x00\x00'  # Hex string "0000000"
        frame_count = 0

        try:
            async for message in websocket:
                if isinstance(message, bytes):
                    frame_buffer.extend(message)
                    delimiter_index = frame_buffer.find(frame_delimiter)
                    while delimiter_index != -1:
                        print(f"Delimiter index: {delimiter_index}")

                        # Split the frame at the delimiter
                        frame_data = frame_buffer[:delimiter_index]
                        frame_buffer = frame_buffer[delimiter_index + len(frame_delimiter):]
                        delimiter_index = frame_buffer.find(frame_delimiter)

                        # Process the frame
                        yuv_frame = np.frombuffer(frame_data, dtype=np.uint8).reshape((240 * 3 // 2, 320))

                        # Convert YUV to BGR
                        bgr_frame = cv2.cvtColor(yuv_frame, cv2.COLOR_YUV2BGR_I420)

                        # Display the frame
                        cv2.imshow('Video Frame', bgr_frame)
                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            break
                        frame_count += 1
                else:
                    # Handle control messages
                    data = json.loads(message)
                    print(data["message"])

        except KeyboardInterrupt:
            print("Ctrl+C pressed. Closing WebSocket connection...")
            await websocket.close()

        finally:
            cv2.destroyAllWindows()

asyncio.get_event_loop().run_until_complete(video_client())
