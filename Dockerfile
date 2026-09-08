FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY public ./public
COPY scripts/build-client.mjs ./scripts/build-client.mjs
RUN node scripts/build-client.mjs

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=5173

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --from=build /build/public ./public
COPY server.mjs ./
COPY lib ./lib

USER node

EXPOSE 5173

CMD ["node", "server.mjs"]
