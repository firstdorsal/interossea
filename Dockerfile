FROM node:lts-alpine3.13
WORKDIR /interossea/
COPY . .
RUN yarn --ignore-engines
ENTRYPOINT [ "node", "index.js" ]