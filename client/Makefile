BROWSERIFY=node_modules/.bin/browserify
WATCHIFY=node_modules/.bin/watchify
KARMA=node_modules/.bin/karma

default: build
all: clean build test

build: src/main.js
	$(BROWSERIFY) src/main.js -v \
                              -o dist/verifyme.js \
                              -t [ babelify --presets [ stage-3 es2015 ] ]

watch: src/main.js
	$(WATCHIFY) src/main.js -v \
                            -o dist/verifyme.js \
                            -t [ babelify --presets [ stage-3 es2015 ] ]

test: test/*.js
	$(KARMA) start karma.conf.js

clean:
	@rm -rf dist/* coverage/*

.PHONY: clean setup-dev setup-production test
