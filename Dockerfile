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
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a working directory
WORKDIR /app

# Create results directory
RUN mkdir -p /app/results

# Copy the container escape check script
COPY container-escape-check.sh /app/

# Make the script executable
RUN chmod +x /app/container-escape-check.sh

# For buildpack builds, the package.json build script will handle running the check
# For direct Docker builds, run the check now
RUN if [ ! -f "/app/package.json" ]; then \
        echo "Running container escape check during Docker build..." && \
        /app/container-escape-check.sh > /app/results/escape-check-output.txt 2>&1 || true && \
        echo "Container escape check completed during build" ; \
    fi

# The results directory will contain the build-time analysis
# No need to run the script at runtime since results are pre-generated

# For buildpack environments, expose port
EXPOSE ${PORT:-3000}

# Default command - will be overridden by buildpack
CMD ["echo", "Container escape check results available. Use buildpack or provide your own entrypoint."] 