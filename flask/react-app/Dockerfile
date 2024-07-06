# flask_react_app/react-app/Dockerfile
FROM node:14

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install

COPY . .

RUN npm run build
EXPOSE 3000
# Serve the React app using a simple static server
#RUN npm install -g serve
#CMD ["serve", "-s", "build"]

# Command to run the development server
CMD ["npm", "start"]