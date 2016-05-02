BABEL=node_modules/.bin/babel
BABEL_NODE=node_modules/.bin/babel-node
BABEL_INSTANBUL=node_modules/.bin/babel-istanbul
MOCHA=node_modules/.bin/_mocha
NODE=node

default: build run
all: clean build run

build: src/main.js
	$(BABEL) -d dist/ src/

watch: src/main.js
	$(BABEL) -w -d dist/ src/

run: dist/main.js
	$(NODE) dist/main.js

clean:
	@rm -rf dist/* coverage/*

setup-dev:
	@npm install

setup-production:
	@npm install --production

.PHONY: clean setup-dev setup-production 
