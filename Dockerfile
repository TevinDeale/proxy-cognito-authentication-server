FROM node:current-alpine3.19
WORKDIR /app
COPY package.json .
COPY yarn.lock .
COPY index.js .
RUN apk update
RUN apk add yarn
RUN yarn install
RUN --mount=type=secret,id=.env,required=true cp /run/secrets/.env /app/.env
EXPOSE 3000
ENTRYPOINT [ "yarn", "start" ]