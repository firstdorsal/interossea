FROM node:lts-alpine3.13
WORKDIR /interossea/
COPY package.json  *.lock ./
RUN yarn
COPY . .
RUN yarn build
ENTRYPOINT [ "yarn", "start" ]