FROM node:lts-alpine3.13
WORKDIR /interossea/
COPY . .
RUN yarn
ENTRYPOINT [ "yarn", "start" ]