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

test: test/**/*.js
	$(BABEL_NODE) $(BABEL_INSTANBUL) cover $(MOCHA) -- test/*

clean:
	@rm -rf dist/* coverage/*

setup:
	@npm install -d

.PHONY: clean setup test watch
