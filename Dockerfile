FROM node:22-slim AS builder

WORKDIR /app
COPY package.json tsconfig.json vite.config.ts index.html ./
COPY shared/ ./shared/
COPY server/ ./server/
COPY src/ ./src/
COPY sample-context/ ./sample-context/

RUN npm install && npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production \
    PORT=8080

RUN groupadd -r siftair && useradd -r -g siftair siftair
COPY --from=builder /app /app
RUN chown -R siftair:siftair /app

USER siftair
EXPOSE 8080
CMD ["node", "--experimental-strip-types", "server/index.ts"]
