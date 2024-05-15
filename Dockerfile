FROM node:current-alpine3.19
VOLUME [ "/rocketbank-dev" ]
COPY package.json package.json
COPY yarn.lock yarn.lock
COPY index.js index.js
COPY var.env .env
RUN apk update
RUN apk add yarn
RUN yarn install
EXPOSE 3000
ENTRYPOINT [ "yarn", "start" ]