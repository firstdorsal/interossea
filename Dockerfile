FROM node:14.15.4-slim
WORKDIR /akkount/
COPY index.js .
COPY package.json .
RUN yarn --ignore-engines
ENTRYPOINT [ "node", "index.js" ]