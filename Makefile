# claudehost — build + install the ClaudeHost.app TCC broker.
#
# IMPORTANT: the app is ad-hoc signed by default, so its TCC identity is its
# cdhash - EVERY rebuild that changes the binary invalidates existing TCC
# grants (Full Disk Access etc.) and you must re-grant in System Settings.
# Rebuild deliberately, not casually. See README.md.
#
# To sign with a real identity instead: make SIGN_ID="Developer ID Application: ..."

APP     := build/ClaudeHost.app
BIN     := $(APP)/Contents/MacOS/claudehost
DEST    := /Applications/ClaudeHost.app
SIGN_ID := -
CFLAGS  := -O2 -Wall -Wextra
LIBS    := -framework Security -framework CoreFoundation

$(BIN): claudehost.c Info.plist
	mkdir -p $(APP)/Contents/MacOS
	cp Info.plist $(APP)/Contents/Info.plist
	cc $(CFLAGS) claudehost.c -o $(BIN) $(LIBS)
	codesign --force --sign $(SIGN_ID) $(APP)
	@echo "Built + signed ($(SIGN_ID)) $(APP)"

.PHONY: install clean
install: $(BIN)
	rm -rf $(DEST)
	ditto $(APP) $(DEST)
	@echo "Installed $(DEST) - if the binary changed, TCC grants must be re-done."

clean:
	rm -rf build
