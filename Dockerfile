FROM node:20-alpine as builder
WORKDIR /app
COPY package*.json ./
ENV HTTP_PROXY=http://172.17.0.1:7890
ENV HTTPS_PROXY=http://172.17.0.1:7890
RUN yarn install
COPY . .

FROM node:20-alpine as sor-runner
WORKDIR /app
COPY --from=builder /app/config.json ./
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/guard.js ./
COPY --from=builder /app/node_modules ./node_modules
CMD sh -c "node guard.js"
