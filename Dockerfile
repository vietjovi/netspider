FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the script
COPY netspider.py .

# Make script executable
RUN chmod +x netspider.py

# Set entrypoint
ENTRYPOINT ["python3", "netspider.py"]
