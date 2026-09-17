# DeskWise Backend Dockerfile
FROM node:20-alpine

WORKDIR /app

# Copy dependency definitions first to leverage layer caching
COPY package*.json ./

# Install production dependencies only
RUN npm install --omit=dev

# Copy backend application source code
COPY . .

# Expose backend server port
EXPOSE 5000

# Start command
CMD ["node", "src/server.js"]
