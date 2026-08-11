FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=5173

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY public ./public
COPY server.mjs ./

USER node

EXPOSE 5173

CMD ["node", "server.mjs"]
