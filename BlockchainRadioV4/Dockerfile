# Blockchain Radio V4 - Docker Image
# 
# Multi-stage build for optimized image size and build caching.

FROM node:20-slim AS zkapp-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/zkapp

# Copy zkapp files
COPY zkapp/package.json zkapp/tsconfig.json ./
RUN npm install

# Copy source and build
COPY zkapp/src ./src
RUN npm run build || true

# ============================================
# Final image
# ============================================
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 for o1js
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy zkapp from builder stage
COPY --from=zkapp-builder /app/zkapp /app/zkapp

# Copy application code
COPY blockchain /app/blockchain
COPY crypto /app/crypto
COPY session /app/session
COPY network /app/network
COPY radio /app/radio

# Create keys directory
RUN mkdir -p /app/keys

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose ports
# 5000-5004: Repeater chain
# 6000: Receiver
# 12345: Producer UDP
# 54321: Radio UDP
EXPOSE 5000 5001 5002 5003 5004 6000 12345 54321

# Default command
CMD ["/bin/bash"]
