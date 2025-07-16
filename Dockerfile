FROM ubuntu:22.04

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Update package list and install required dependencies
RUN apt-get update && \
    apt-get install -y \
    bash \
    coreutils \
    findutils \
    grep \
    procps \
    net-tools \
    iproute2 \
    libcap2-bin \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Copy the container escape check script
COPY container-escape-check.sh /app/

# Make the script executable
RUN chmod +x /app/container-escape-check.sh

# Set the script as the entry point
ENTRYPOINT ["/app/container-escape-check.sh"] 