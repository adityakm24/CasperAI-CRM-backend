# for TypeScript development
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

RUN mkdir -p /app/dist/Keys && chmod -R 755 /app/dist/Keys
RUN node -e 'require("./dist/Keys/generateKeys").generateKeys()'

EXPOSE 3001

CMD ["node", "dist/server.js"]
