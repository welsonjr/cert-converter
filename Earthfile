FROM rust:1.62-slim
WORKDIR /cert-converter
RUN apt-get update

deps:
    RUN apt-get install -y curl build-essential libssl-dev npm nodejs pkg-config

source:
    FROM +deps
    COPY assets ./assets
    COPY test ./test
    COPY src ./src
    COPY Cargo.toml ./
    COPY package.json ./package.json
   
build:
    FROM +source
    RUN npm install
    RUN npm run build-release
    SAVE ARTIFACT native/index.node AS LOCAL native/index.node