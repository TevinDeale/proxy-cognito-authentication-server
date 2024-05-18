FROM node:current-alpine3.19
COPY package.json .
COPY yarn.lock .
COPY index.js .
COPY var.env .env
RUN apk update
RUN apk add yarn
RUN yarn install
EXPOSE 3000
ENTRYPOINT [ "yarn", "start" ]