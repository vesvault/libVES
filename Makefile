
all:
	node build.js
	$(MAKE) -C WasmOQS/
	$(MAKE) -C WasmECDH/

# A release from source, third-party code included: see build-release.sh
release:
	./build-release.sh

.PHONY: all release
