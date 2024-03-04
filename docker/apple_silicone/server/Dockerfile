# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir cryze-server

# Run the start_server.py script
CMD ["cryze-server"]