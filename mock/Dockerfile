# Use Node.js 18 Alpine for a lightweight container
FROM node:18-alpine

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

# Create a non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S mockserver -u 1001

# Change ownership of the app directory and logs
RUN chown -R mockserver:nodejs /app /logs

# Create a startup script to handle log directory permissions
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'mkdir -p /logs' >> /app/start.sh && \
    echo 'chown -R mockserver:nodejs /logs' >> /app/start.sh && \
    echo 'exec su-exec mockserver "$@"' >> /app/start.sh && \
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
