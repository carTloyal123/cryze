from PIL import Image
import io
import numpy as np
import cv2

# Load the binary data from the file
with open('frames/message_11.bin', 'rb') as f:
    binary_data = f.read()

# Convert the binary data to a bytes-like object
bytes_data = io.BytesIO(binary_data)

# Open the bytes-like object as an image
img = Image.open(bytes_data)

# Convert the image to a numpy array
frame_array = np.array(img)

# Display the frame
cv2.imshow('Frame', frame_array)
cv2.waitKey(0)
cv2.destroyAllWindows()