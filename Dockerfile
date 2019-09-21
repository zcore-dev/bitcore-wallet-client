FROM node:carbon
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install
COPY lerna.json ./

COPY ./packages/bitcore-wallet-client/package.json ./packages/bitcore-wallet-client/package.json
COPY ./packages/crypto-wallet-core/package.json ./packages/crypto-wallet-core/package.json

RUN ./node_modules/.bin/lerna bootstrap

COPY . .
EXPOSE 3000
EXPOSE 8100
CMD ["./node_modules/.bin/lerna", "run", "start"]
