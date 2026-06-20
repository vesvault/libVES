
all:
	node build.js
	$(MAKE) -C WasmOQS/
	$(MAKE) -C WasmECDH/
