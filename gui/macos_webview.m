#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface AppDelegate : NSObject <NSApplicationDelegate, WKUIDelegate, WKNavigationDelegate>
@property (nonatomic, strong) NSWindow *window;
@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, copy) NSString *targetURL;
@property (nonatomic, copy) NSString *windowTitle;
@end

@implementation AppDelegate

- (void)setupMenuBar {
    NSMenu *mainMenu = [[NSMenu alloc] init];

    NSMenuItem *appItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:appItem];
    NSMenu *appMenu = [[NSMenu alloc] init];
    [appMenu addItemWithTitle:@"Quit WiFi Signal Analyzer"
                       action:@selector(terminate:)
                keyEquivalent:@"q"];
    [appItem setSubmenu:appMenu];

    NSMenuItem *editItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:editItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editItem setSubmenu:editMenu];

    NSMenuItem *winItem = [[NSMenuItem alloc] init];
    [mainMenu addItem:winItem];
    NSMenu *winMenu = [[NSMenu alloc] initWithTitle:@"Window"];
    [winMenu addItemWithTitle:@"Close" action:@selector(performClose:) keyEquivalent:@"w"];
    [winItem setSubmenu:winMenu];

    [NSApp setMainMenu:mainMenu];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [self setupMenuBar];

    NSRect frame = NSMakeRect(0, 0, 1140, 820);
    NSWindowStyleMask style = NSWindowStyleMaskTitled
                            | NSWindowStyleMaskClosable
                            | NSWindowStyleMaskMiniaturizable
                            | NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    [self.window setTitle:(self.windowTitle ?: @"WiFi Signal & Stability Analyzer")];
    [self.window setMinSize:NSMakeSize(760, 560)];
    [self.window center];

    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    self.webView = [[WKWebView alloc] initWithFrame:[[self.window contentView] bounds]
                                      configuration:config];
    [self.webView setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
    [self.webView setUIDelegate:self];
    [self.webView setNavigationDelegate:self];
    [self.window setContentView:self.webView];

    NSURL *url = [NSURL URLWithString:self.targetURL];
    if (url) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url
                                             cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                         timeoutInterval:15.0];
        [self.webView loadRequest:req];
    }

    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (WKWebView *)webView:(WKWebView *)webView
    createWebViewWithConfiguration:(WKWebViewConfiguration *)configuration
               forNavigationAction:(WKNavigationAction *)navigationAction
                    windowFeatures:(WKWindowFeatures *)windowFeatures {
    if (!navigationAction.targetFrame.isMainFrame && navigationAction.request.URL) {
        [[NSWorkspace sharedWorkspace] openURL:navigationAction.request.URL];
    }
    return nil;
}

@end

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <url> [title]\n", argv[0]);
        return 1;
    }
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        AppDelegate *delegate = [[AppDelegate alloc] init];
        delegate.targetURL = [NSString stringWithUTF8String:argv[1]];
        if (argc >= 3) {
            delegate.windowTitle = [NSString stringWithUTF8String:argv[2]];
        }
        [NSApp setDelegate:delegate];
        [NSApp run];
    }
    return 0;
}
