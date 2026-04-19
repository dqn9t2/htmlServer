FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY server.js ./

RUN mkdir -p data projects tmp

EXPOSE 3000

ENV PORT=3000 \
    ADMIN_PASSWORD=admin \
    SESSION_SECRET=""

CMD ["node", "server.js"]
