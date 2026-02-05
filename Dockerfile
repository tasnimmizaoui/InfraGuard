# ============================================
# InfraGuard - AWS Security Scanner
# Multi-stage Docker build for optimized image
# ============================================

# Stage 1: Builder
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Metadata
LABEL maintainer="tasnimmizaoui1@gmail.com"
LABEL description="InfraGuard - AWS Cloud Security Monitoring with Shift-Left"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY infra_guard/ ./infra_guard/
COPY main.py .
COPY lambda_handler.py .
COPY docker-entrypoint.sh .

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV INFRAGUARD_LOG_LEVEL=INFO
ENV PYTHONDONTWRITEBYTECODE=1

# Create non-root user for security
RUN useradd -m -u 1000 infraguard && \
    chown -R infraguard:infraguard /app

# Switch to non-root user
USER infraguard

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import infra_guard; print('OK')" || exit 1

# Default command
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["--help"]
