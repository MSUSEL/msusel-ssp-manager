# Use Node.js 18 Alpine for a lightweight container
FROM node:18-alpine

# Accept build arguments for user ownership (following Flask container pattern)
ARG HOST_UID
ARG HOST_GID

# Set working directory
WORKDIR /app

# Create logs directory
RUN mkdir -p /logs

# Copy package files first for better Docker layer caching
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application source code
COPY server2.js ./
COPY README.md ./

# Create a non-root user for security using HOST_UID/HOST_GID (following Flask container pattern)
# Use HOST_UID and HOST_GID if provided, otherwise fallback to 1001 for compatibility
# For UID 1000, use existing 'node' user; for others, create new user
RUN if [ "${HOST_UID:-1001}" = "1000" ]; then \
        echo "Using existing node user with UID 1000"; \
        MOCKSERVER_USER=node; \
    else \
        adduser -S mockserver -u ${HOST_UID:-1001}; \
        MOCKSERVER_USER=mockserver; \
    fi && \
    echo "MOCKSERVER_USER=$MOCKSERVER_USER" > /app/user.env

# Change ownership of the app directory and logs using the determined user
RUN . /app/user.env && chown -R ${HOST_UID:-1001}:${HOST_GID:-1001} /app /logs

# Create a startup script to handle log directory permissions with proper ownership
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo '. /app/user.env' >> /app/start.sh && \
    echo 'mkdir -p /logs' >> /app/start.sh && \
    echo "chown -R ${HOST_UID:-1001}:${HOST_GID:-1001} /logs" >> /app/start.sh && \
    echo 'exec su-exec $MOCKSERVER_USER "$@"' >> /app/start.sh && \
    chmod +x /app/start.sh

# Install su-exec for proper user switching
RUN apk add --no-cache su-exec

# Don't switch user here - let the startup script handle it

# Expose port 8000
EXPOSE 8000

# Set environment variables with defaults
ENV OPA_SERVER_URL=http://opa:8181
ENV USE_REAL_OPA=true
ENV NODE_ENV=production

# Health check to ensure the server is running
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8000/health || exit 1

# Use the startup script as entrypoint
ENTRYPOINT ["/app/start.sh"]

# Start the enhanced mock server
CMD ["node", "server2.js"]
