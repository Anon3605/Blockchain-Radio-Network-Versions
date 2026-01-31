FROM kalilinux/kali-rolling

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 (required for o1js)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r requirements.txt --break-system-packages

# Install zkApp CLI and o1js globally
RUN npm install -g zkapp-cli o1js

# Copy application code
COPY . /app/

# Initialize zkApp project (if not already done)
WORKDIR /app/zkapp

# Install zkApp dependencies
RUN if [ -f "package.json" ]; then \
    npm install; \
    fi

# If package.json doesn't exist, create it and install o1js
RUN if [ ! -f "package.json" ]; then \
    npm init -y && \
    npm install o1js@1.9.0; \
    fi

# Build TypeScript code if src exists
RUN if [ -d "src" ]; then \
    npm run build || true; \
    fi

WORKDIR /app

# Expose ports for different node types
EXPOSE 5000 5001 5002 5003 5004 6000 8080

# Default command (overridden by docker-compose)
CMD ["/bin/bash"]