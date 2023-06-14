# Use an official Python runtime as the base image
FROM python:3.8

# Set the working directory in the container
WORKDIR /app

# Copy the rest of the application's source code into the container
COPY README.md .
COPY setup.py .
COPY farmhand .
# Install the Python dependencies
RUN pip install --no-cache-dir .

ENTRYPOINT ["python", "farmhand.py"]
