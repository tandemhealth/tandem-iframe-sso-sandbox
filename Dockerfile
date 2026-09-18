FROM node:22-alpine

WORKDIR /app
COPY package.json ./
COPY sandbox ./sandbox

USER node
ENV SANDBOX_HOST=0.0.0.0 SANDBOX_PORT=8000
EXPOSE 8000
# Pass configuration with --env-file .env; publish the port on 127.0.0.1 only.
CMD ["node", "sandbox/server.js"]
