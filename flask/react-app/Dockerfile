# Use an official Node runtime as a parent image
FROM node:16-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed packages
RUN npm install --legacy-peer-deps
#RUN npm install react-router-dom@latest

# Expose port 3000 to the outside world
EXPOSE 3000

# Run Vite development server
CMD ["npm", "run", "dev"]
