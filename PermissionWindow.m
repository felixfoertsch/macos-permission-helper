#import "PermissionWindow.h"

#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <CoreGraphics/CoreGraphics.h>
#import <EventKit/EventKit.h>

@interface PermissionAppDelegate : NSObject <NSApplicationDelegate>
@property(strong) NSWindow *window;
@property(strong) NSMutableDictionary<NSString *, NSTextField *> *statuses;
@end

@implementation PermissionAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
	(void)notification;
	self.statuses = [NSMutableDictionary dictionary];
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
	NSTextField *label = [NSTextField labelWithString:name];
	label.font = [NSFont systemFontOfSize:13 weight:NSFontWeightMedium];
	[label setContentHuggingPriority:NSLayoutPriorityDefaultLow forOrientation:NSLayoutConstraintOrientationHorizontal];
	NSTextField *status = [NSTextField labelWithString:@"Unknown"];
	status.alignment = NSTextAlignmentRight;
	status.frame = NSMakeRect(0, 0, 110, 22);
	NSButton *button = [NSButton buttonWithTitle:@"Grant…" target:self action:action];
	[row addArrangedSubview:label];
	[row addArrangedSubview:status];
	[row addArrangedSubview:button];
	self.statuses[key] = status;
	[stack addArrangedSubview:row];
	[row.widthAnchor constraintEqualToAnchor:stack.widthAnchor constant:-48].active = YES;
	[status.widthAnchor constraintEqualToConstant:110].active = YES;
	[button.widthAnchor constraintEqualToConstant:90].active = YES;
}

- (void)openSettings:(NSString *)url {
	[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:url]];
}

- (void)openFullDiskAccess:(id)sender {
	(void)sender;
	[self openSettings:@"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"];
}

- (void)requestLocalNetwork:(id)sender {
	(void)sender;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		NSURL *url = [NSURL URLWithString:@"http://192.168.23.1/"];
		NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithURL:url];
		[task resume];
	});
	[self openSettings:@"x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork"];
}

- (void)requestReminders:(id)sender {
	(void)sender;
	EKEventStore *store = [[EKEventStore alloc] init];
	[store requestFullAccessToRemindersWithCompletion:^(BOOL granted, NSError *error) {
		(void)error;
		dispatch_async(dispatch_get_main_queue(), ^{
			self.statuses[@"reminders"].stringValue = granted ? @"Granted" : @"Not granted";
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
	self.statuses[@"fda"].stringValue = @"Check Settings";
	self.statuses[@"local"].stringValue = @"Check Settings";
	EKAuthorizationStatus reminders = [EKEventStore authorizationStatusForEntityType:EKEntityTypeReminder];
	self.statuses[@"reminders"].stringValue = reminders == EKAuthorizationStatusFullAccess ? @"Granted" : @"Not granted";
	self.statuses[@"accessibility"].stringValue = AXIsProcessTrusted() ? @"Granted" : @"Not granted";
	self.statuses[@"screen"].stringValue = CGPreflightScreenCaptureAccess() ? @"Granted" : @"Not granted";
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
