#import "PermissionWindow.h"

#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import <EventKit/EventKit.h>
#import <Network/Network.h>
#include <fcntl.h>
#include <unistd.h>

static nw_connection_t localNetworkConnection;

@interface PermissionAppDelegate : NSObject <NSApplicationDelegate>
@property(strong) NSWindow *window;
@property(strong) NSMutableDictionary<NSString *, NSTextField *> *statuses;
@property(strong) NSMutableDictionary<NSString *, NSView *> *indicators;
@end

@implementation PermissionAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
	(void)notification;
	NSMenu *menuBar = [[NSMenu alloc] init];
	NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
	[menuBar addItem:appMenuItem];
	NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"macOS Permission Helper"];
	[appMenu addItemWithTitle:@"About macOS Permission Helper" action:@selector(orderFrontStandardAboutPanel:) keyEquivalent:@""];
	[appMenu addItem:[NSMenuItem separatorItem]];
	[appMenu addItemWithTitle:@"Quit macOS Permission Helper" action:@selector(terminate:) keyEquivalent:@"q"];
	appMenuItem.submenu = appMenu;
	NSApp.mainMenu = menuBar;

	self.statuses = [NSMutableDictionary dictionary];
	self.indicators = [NSMutableDictionary dictionary];
	self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 620, 430)
		styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
		backing:NSBackingStoreBuffered defer:NO];
	self.window.title = @"macOS Permission Helper";
	[self.window center];

	NSStackView *stack = [[NSStackView alloc] initWithFrame:self.window.contentView.bounds];
	stack.orientation = NSUserInterfaceLayoutOrientationVertical;
	stack.alignment = NSLayoutAttributeLeading;
	stack.spacing = 14;
	stack.edgeInsets = NSEdgeInsetsMake(24, 24, 24, 24);
	stack.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
	[self.window.contentView addSubview:stack];

	NSTextField *intro = [NSTextField wrappingLabelWithString:@"Grant permissions once to this signed helper. OpenCode2 and its tools run beneath this stable identity, so grants survive OpenCode2 updates."];
	intro.maximumNumberOfLines = 3;
	[stack addArrangedSubview:intro];

	[self addPermission:@"Full Disk Access" key:@"fda" action:@selector(openFullDiskAccess:) stack:stack];
	[self addPermission:@"Local Network" key:@"local" action:@selector(requestLocalNetwork:) stack:stack];
	[self addPermission:@"Reminders" key:@"reminders" action:@selector(requestReminders:) stack:stack];
	[self addPermission:@"Accessibility" key:@"accessibility" action:@selector(requestAccessibility:) stack:stack];
	[self addPermission:@"Screen & System Audio Recording" key:@"screen" action:@selector(requestScreenRecording:) stack:stack];

	NSButton *refresh = [NSButton buttonWithTitle:@"Refresh Status" target:self action:@selector(refresh:)];
	[stack addArrangedSubview:refresh];
	NSTextField *footer = [NSTextField wrappingLabelWithString:@"Full Disk Access and Local Network have no reliable public status API. Their buttons open Settings or trigger a local-network request; return here after approving, then restart helper services."];
	footer.textColor = NSColor.secondaryLabelColor;
	footer.maximumNumberOfLines = 3;
	[stack addArrangedSubview:footer];

	[self refresh:nil];
	[self.window makeKeyAndOrderFront:nil];
	[NSApp activateIgnoringOtherApps:YES];
}

- (void)addPermission:(NSString *)name key:(NSString *)key action:(SEL)action stack:(NSStackView *)stack {
	NSStackView *row = [NSStackView stackViewWithViews:@[]];
	row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
	row.spacing = 12;
	NSView *indicator = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 8, 8)];
	indicator.wantsLayer = YES;
	indicator.layer.cornerRadius = 4;
	NSTextField *label = [NSTextField labelWithString:name];
	label.font = [NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
	NSTextField *status = [NSTextField labelWithString:@"Unknown"];
	status.alignment = NSTextAlignmentLeft;
	NSButton *button = [NSButton buttonWithTitle:@"Grant…" target:self action:action];
	[row addArrangedSubview:indicator];
	[row addArrangedSubview:label];
	[row addArrangedSubview:status];
	[row addArrangedSubview:button];
	self.statuses[key] = status;
	self.indicators[key] = indicator;
	[stack addArrangedSubview:row];
	[row.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-48].active = YES;
	[indicator.widthAnchor constraintEqualToConstant:8].active = YES;
	[indicator.heightAnchor constraintEqualToConstant:8].active = YES;
	[label.widthAnchor constraintEqualToConstant:245].active = YES;
	[status.widthAnchor constraintEqualToConstant:125].active = YES;
	[button.widthAnchor constraintEqualToConstant:90].active = YES;
}

- (void)setStatus:(NSString *)status color:(NSColor *)color key:(NSString *)key {
	self.statuses[key].stringValue = status;
	self.indicators[key].layer.backgroundColor = color.CGColor;
}

- (void)openSettings:(NSString *)url {
	[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:url]];
}

- (void)showInstructions:(NSString *)text {
	NSAlert *alert = [[NSAlert alloc] init];
	alert.messageText = @"Manual approval required";
	alert.informativeText = text;
	[alert addButtonWithTitle:@"Open System Settings"];
	[alert addButtonWithTitle:@"Cancel"];
	if ([alert runModal] == NSAlertFirstButtonReturn) {
		[self openSettings:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
	}
}

- (void)openFullDiskAccess:(id)sender {
	(void)sender;
	[self showInstructions:@"Full Disk Access has no request API. In System Settings, click +, choose /Applications/MacOSPermissionHelper.app, then enable its switch."];
}

- (void)requestLocalNetwork:(id)sender {
	(void)sender;
	if (localNetworkConnection) nw_connection_cancel(localNetworkConnection);
	nw_endpoint_t endpoint = nw_endpoint_create_host("192.168.23.20", "22872");
	nw_parameters_t parameters = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
	localNetworkConnection = nw_connection_create(endpoint, parameters);
	[self setStatus:@"Checking…" color:NSColor.systemYellowColor key:@"local"];
	nw_connection_set_queue(localNetworkConnection, dispatch_get_main_queue());
	nw_connection_set_state_changed_handler(localNetworkConnection, ^(nw_connection_state_t state, nw_error_t error) {
		if (state == nw_connection_state_ready) {
			[self setStatus:@"Access verified" color:NSColor.systemGreenColor key:@"local"];
			nw_connection_cancel(localNetworkConnection);
		}
		if (state == nw_connection_state_failed || state == nw_connection_state_waiting) {
			nw_path_t path = nw_connection_copy_current_path(localNetworkConnection);
			BOOL denied = path && nw_path_get_unsatisfied_reason(path) == nw_path_unsatisfied_reason_local_network_denied;
			(void)error;
			[self setStatus:(denied ? @"Policy denied" : @"Unclear") color:(denied ? NSColor.systemRedColor : NSColor.systemYellowColor) key:@"local"];
		}
	});
	nw_connection_start(localNetworkConnection);
}

- (void)checkFullDiskAccess {
	NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Mail"];
	int fd = open(path.fileSystemRepresentation, O_RDONLY | O_DIRECTORY);
	if (fd >= 0) {
		close(fd);
		[self setStatus:@"Access verified" color:NSColor.systemGreenColor key:@"fda"];
	} else if (errno == EACCES || errno == EPERM) {
		[self setStatus:@"Not granted" color:NSColor.systemRedColor key:@"fda"];
	} else {
		[self setStatus:@"Unclear" color:NSColor.systemYellowColor key:@"fda"];
	}
}

- (void)requestReminders:(id)sender {
	(void)sender;
	EKEventStore *store = [[EKEventStore alloc] init];
	[store requestFullAccessToRemindersWithCompletion:^(BOOL granted, NSError *error) {
		(void)error;
		dispatch_async(dispatch_get_main_queue(), ^{
			[self setStatus:(granted ? @"Granted" : @"Not granted") color:(granted ? NSColor.systemGreenColor : NSColor.systemRedColor) key:@"reminders"];
		});
	}];
}

- (void)requestAccessibility:(id)sender {
	(void)sender;
	NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES};
	AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}

- (void)requestScreenRecording:(id)sender {
	(void)sender;
	CGRequestScreenCaptureAccess();
}

- (void)refresh:(id)sender {
	(void)sender;
	[self checkFullDiskAccess];
	[self requestLocalNetwork:nil];
	EKAuthorizationStatus reminders = [EKEventStore authorizationStatusForEntityType:EKEntityTypeReminder];
	BOOL remindersGranted = reminders == EKAuthorizationStatusFullAccess;
	[self setStatus:(remindersGranted ? @"Granted" : @"Not granted") color:(remindersGranted ? NSColor.systemGreenColor : NSColor.systemRedColor) key:@"reminders"];
	BOOL accessibility = AXIsProcessTrusted();
	[self setStatus:(accessibility ? @"Granted" : @"Not granted") color:(accessibility ? NSColor.systemGreenColor : NSColor.systemRedColor) key:@"accessibility"];
	BOOL screen = CGPreflightScreenCaptureAccess();
	[self setStatus:(screen ? @"Granted" : @"Not granted") color:(screen ? NSColor.systemGreenColor : NSColor.systemRedColor) key:@"screen"];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
	(void)sender;
	return YES;
}

@end

int run_permission_window(void) {
	@autoreleasepool {
		NSApplication *app = [NSApplication sharedApplication];
		PermissionAppDelegate *delegate = [[PermissionAppDelegate alloc] init];
		app.delegate = delegate;
		[app setActivationPolicy:NSApplicationActivationPolicyRegular];
		[app run];
	}
	return 0;
}
