# macOS Permission Helper — build + install stable TCC broker.

APP     := build/MacOSPermissionHelper.app
BIN     := $(APP)/Contents/MacOS/macos-permission-helper
DEST    := /Applications/MacOSPermissionHelper.app
SIGN_ID ?= Developer ID Application: Felix Foertsch (NG5W75WE8U)
CFLAGS  := -O2 -Wall -Wextra
LIBS    := -framework Security -framework CoreFoundation

$(BIN): claudehost.c Info.plist
	mkdir -p $(APP)/Contents/MacOS
	cp Info.plist $(APP)/Contents/Info.plist
	cc $(CFLAGS) claudehost.c -o $(BIN) $(LIBS)
	codesign --force --sign "$(SIGN_ID)" $(APP)
	@echo "Built + signed ($(SIGN_ID)) $(APP)"

.PHONY: install clean
install: $(BIN)
	rm -rf $(DEST)
	ditto $(APP) $(DEST)
	@echo "Installed $(DEST) with stable signing identity $(SIGN_ID)."

clean:
	rm -rf build
