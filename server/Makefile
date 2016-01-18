BABEL=node_modules/.bin/babel
BABEL_NODE=node_modules/.bin/babel-node
BABEL_INSTANBUL=node_modules/.bin/babel-istanbul
MOCHA=node_modules/.bin/_mocha
NODE=node

default: build run
all: build test run

build: src/main.js
	$(BABEL) -d dist/ src/

watch: src/main.js
	$(BABEL) -w -d dist/ src/

test: test/**/*.js
	$(BABEL_NODE) $(BABEL_INSTANBUL) cover $(MOCHA) -- test/*

run: dist/main.js
	$(NODE) dist/main.js

clean:
	@rm -rf dist/* coverage/*

setup:
	@npm install -d

.PHONY: clean setup run test watch
