BABEL=node_modules/.bin/babel
BABEL_NODE=node_modules/.bin/babel-node
BABEL_INSTANBUL=node_modules/.bin/babel-istanbul
MOCHA=node_modules/.bin/_mocha

default: build
all: clean build test

build: src/check.js
	$(BABEL) -d dist/ src/

watch: src/check.js
	$(BABEL) -w -d dist/ src/

test:
	$(BABEL_NODE) $(BABEL_INSTANBUL) cover $(MOCHA) -- test/*

clean:
	@rm -rf dist/* coverage/*

setup-dev:
	@npm install

setup-production:
	@npm install --production

.PHONY: clean setup-dev setup-production test
