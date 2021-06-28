FROM node:lts-alpine3.13
WORKDIR /akkount/
COPY index.js .
COPY package.json .
RUN yarn --ignore-engines
ENTRYPOINT [ "node", "index.js" ]