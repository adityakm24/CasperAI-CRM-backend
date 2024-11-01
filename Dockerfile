# ---- Builder Stage ----
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install
COPY . .
RUN npm run build

# ---- Production Image ----
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --production

COPY --from=builder /app/dist ./dist
COPY src/Keys/*.pem /app/dist/Keys


EXPOSE 3001

ENTRYPOINT ["node"]
CMD ["dist/server.js"]
