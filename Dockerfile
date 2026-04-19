FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY server.js ./

RUN mkdir -p data projects tmp

EXPOSE 3001

ENV PORT=3001 \
    ADMIN_PASSWORD=Phdq861064 \
    SESSION_SECRET="admin"

CMD ["node", "server.js"]
