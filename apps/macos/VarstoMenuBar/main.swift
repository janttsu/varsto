// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Varsto for macOS: a native app with its own window (the interface rendered
// by WebKit inside the app, no browser involved), a menu-bar item, and the
// `varsto` binary in Contents/Helpers, which this app starts and supervises as the
// background service and which doubles as the command-line tool.
// Built on a Mac with apps/macos/build.sh (Xcode command line tools, rustup).

import AppKit
import Foundation
import ServiceManagement
import WebKit

final class ServiceClient {
    let home: URL
    init(home: URL) { self.home = home }

    struct Info { let pid: Int32; let port: Int; let token: String }

    func info() -> Info? {
        let url = home.appendingPathComponent("service.json")
        guard let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pid = obj["pid"] as? Int32, let port = obj["port"] as? Int, let token = obj["token"] as? String
        else { return nil }
        return Info(pid: pid, port: port, token: token)
    }

    func call(_ method: String, _ path: String, body: [String: Any]? = nil) -> [String: Any]? {
        guard let i = info(), let url = URL(string: "http://127.0.0.1:\(i.port)\(path)") else { return nil }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 600
        req.setValue(i.token, forHTTPHeaderField: "X-Varsto-Token")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body = body { req.httpBody = try? JSONSerialization.data(withJSONObject: body) }
        let sem = DispatchSemaphore(value: 0)
        var result: [String: Any]?
        URLSession.shared.dataTask(with: req) { data, _, _ in
            if let d = data { result = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] }
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 605)
        return result
    }

    func uiURL() -> URL? {
        guard let i = info() else { return nil }
        return URL(string: "http://127.0.0.1:\(i.port)/?token=\(i.token)")
    }
}

/// The main window: the local interface in a WebKit view.
final class MainWindow: NSWindowController, WKNavigationDelegate, WKUIDelegate, NSWindowDelegate {
    let web: WKWebView
    var loadedURL = ""

    init() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent() // the session token never touches disk
        web = WKWebView(frame: .zero, configuration: config)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 760),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable],
                              backing: .buffered, defer: false)
        window.title = "Varsto"
        window.minSize = NSSize(width: 720, height: 480)
        window.center()
        window.setFrameAutosaveName("VarstoMain")
        window.contentView = web
        super.init(window: window)
        window.delegate = self
        web.navigationDelegate = self
        web.uiDelegate = self
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func show(url: URL?) {
        if let url = url, url.absoluteString != loadedURL {
            loadedURL = url.absoluteString
            web.load(URLRequest(url: url))
        } else if web.url == nil {
            web.loadHTMLString("<html><body style='font-family:-apple-system;padding:2em;color:#334155'><h2>Starting the Varsto service…</h2><p>This window fills in a moment.</p></body></html>", baseURL: nil)
        }
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // Downloads (Open a file) and external links leave the window.
    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if navigationResponse.canShowMIMEType { decisionHandler(.allow); return }
        if let url = navigationResponse.response.url { NSWorkspace.shared.open(url) }
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = navigationAction.request.url, let host = url.host, host != "127.0.0.1", host != "localhost" {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    // JavaScript alert/confirm/prompt used by the interface, as native panels.
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = message; a.runModal(); completionHandler()
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = message
        a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        completionHandler(a.runModal() == .alertFirstButtonReturn)
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) {
        let a = NSAlert(); a.messageText = prompt
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 24))
        field.stringValue = defaultText ?? ""
        a.accessoryView = field
        a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        completionHandler(a.runModal() == .alertFirstButtonReturn ? field.stringValue : nil)
    }

    // Closing the window keeps the app running in the menu bar.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var process: Process?
    var client: ServiceClient!
    var home: URL!
    var binary: URL!
    var timer: Timer?
    let main = MainWindow()
    let statusMenuItem = NSMenuItem(title: "Starting…", action: nil, keyEquivalent: "")
    let pauseItem = NSMenuItem(title: "Pause syncing", action: #selector(togglePause), keyEquivalent: "")
    let updateNote = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let loginItem = NSMenuItem(title: "Start at login", action: #selector(toggleLogin), keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        home = support.appendingPathComponent("Varsto")
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        binary = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/varsto")
        client = ServiceClient(home: home)

        buildMainMenu()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            // The brand mark as a template image (brand/menubar-template.svg), falling back to a symbol.
            let image = Bundle.main.url(forResource: "menubar-template", withExtension: "png").flatMap { NSImage(contentsOf: $0) }
                ?? NSImage(systemSymbolName: "lock.icloud", accessibilityDescription: "Varsto")
            image?.isTemplate = true
            image?.size = NSSize(width: 18, height: 18)
            button.image = image
        }
        let menu = NSMenu()
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)
        menu.addItem(.separator())
        menu.addItem(withTitle: "Open Varsto", action: #selector(openUI), keyEquivalent: "o")
        menu.addItem(withTitle: "Sync now", action: #selector(syncNow), keyEquivalent: "s")
        menu.addItem(pauseItem)
        menu.addItem(withTitle: "Check for updates", action: #selector(checkUpdates), keyEquivalent: "")
        updateNote.isEnabled = false
        updateNote.isHidden = true
        menu.addItem(updateNote)
        menu.addItem(.separator())
        menu.addItem(withTitle: "Install command-line tool…", action: #selector(installCli), keyEquivalent: "")
        menu.addItem(loginItem)
        menu.addItem(withTitle: "Quit Varsto", action: #selector(quit), keyEquivalent: "q")
        for item in menu.items { item.target = self }
        statusItem.menu = menu

        NSApp.servicesProvider = FinderService(owner: self)
        NSUpdateDynamicServices()
        ensureService()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        if ProcessInfo.processInfo.environment["VARSTO_NO_OPEN"] == nil {
            // Not when Finder started us to open a placeholder.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { if !self.launchedForFiles { self.openUI() } }
        }
    }

    // ----- Finder: placeholders and the Services menu ------------------------

    var launchedForFiles = false

    /// Double-clicked placeholders: download each file, then open it.
    func application(_ application: NSApplication, open urls: [URL]) {
        launchedForFiles = true
        actOnPaths("fetch", urls.map { $0.path }, openAfter: true)
    }

    func actOnPaths(_ action: String, _ paths: [String], openAfter: Bool) {
        guard !paths.isEmpty else { return }
        DispatchQueue.global().async {
            var r: [String: Any]?
            // Started just now by Finder: the service may still be coming up.
            for _ in 0..<40 {
                r = self.client.call("POST", "/api/paths", body: ["action": action, "paths": paths])
                if r != nil { break }
                Thread.sleep(forTimeInterval: 0.5)
            }
            DispatchQueue.main.async { self.report(action, paths, r, openAfter) }
        }
    }

    func report(_ action: String, _ paths: [String], _ r: [String: Any]?, _ openAfter: Bool) {
        let title = action == "fetch" ? "Could not download" : "Could not free up space"
        guard let r = r else { alert(title, "The Varsto service did not answer. Open Varsto and try again."); return }
        if let e = r["error"] as? String {
            if e.contains("locked") {
                promptUnlockIfNeeded()
                if client.call("GET", "/api/state")?["unlocked"] as? Bool == true { actOnPaths(action, paths, openAfter: openAfter) }
            } else {
                alert(title, e)
            }
            return
        }
        var failed: [String] = []
        for x in r["results"] as? [[String: Any]] ?? [] {
            let p = x["path"] as? String ?? ""
            if x["ok"] as? Bool == true {
                if openAfter {
                    let suffix = ".varsto-placeholder"
                    let real = p.hasSuffix(suffix) ? String(p.dropLast(suffix.count)) : p
                    NSWorkspace.shared.open(URL(fileURLWithPath: real))
                }
            } else {
                failed.append("\((p as NSString).lastPathComponent): \(x["error"] as? String ?? "failed")")
            }
        }
        if !failed.isEmpty { alert(title, failed.joined(separator: "\n")) }
    }

    func alert(_ title: String, _ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert(); a.messageText = title; a.informativeText = text; a.runModal()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openUI()
        return true
    }

    func buildMainMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem(); mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About Varsto", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide Varsto", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let quitItem = appMenu.addItem(withTitle: "Quit Varsto", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        appItem.submenu = appMenu
        let editItem = NSMenuItem(); mainMenu.addItem(editItem)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        let windowItem = NSMenuItem(); mainMenu.addItem(windowItem)
        let win = NSMenu(title: "Window")
        let showItem = win.addItem(withTitle: "Varsto", action: #selector(openUI), keyEquivalent: "1")
        showItem.target = self
        win.addItem(withTitle: "Minimize", action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = win
        NSApp.mainMenu = mainMenu
    }

    func ensureService() {
        if let p = process, p.isRunning { return }
        if client.info() != nil, client.call("GET", "/api/service") != nil { return } // started elsewhere (launch agent)
        let p = Process()
        p.executableURL = binary
        p.arguments = ["--home", home.path, "service", "run", "--port", "0", "--interval", "300"]
        let logPath = home.appendingPathComponent("service.log").path
        if !FileManager.default.fileExists(atPath: logPath) { FileManager.default.createFile(atPath: logPath, contents: nil) }
        p.standardOutput = FileHandle(forWritingAtPath: logPath)
        p.standardError = p.standardOutput
        p.terminationHandler = { [weak self] proc in
            // 75 = restart after a self-update; anything else: restart after a pause.
            DispatchQueue.main.asyncAfter(deadline: .now() + (proc.terminationStatus == 75 ? 0.5 : 3)) { self?.ensureService() }
        }
        try? p.run()
        process = p
    }

    var refreshing = false
    func refresh() {
        ensureService()
        if refreshing { return }
        refreshing = true
        // The service may be busy syncing: never block the main thread on it.
        DispatchQueue.global().async { [weak self] in
            let state = self?.client.call("GET", "/api/state")
            DispatchQueue.main.async { self?.refreshing = false; self?.apply(state: state) }
        }
    }

    func apply(state: [String: Any]?) {
        guard let state = state else { statusMenuItem.title = "Service starting…"; return }
        if main.window?.isVisible == true, main.loadedURL.isEmpty { main.show(url: client.uiURL()) }
        if state["has_vault"] as? Bool != true { statusMenuItem.title = "Not set up yet: open Varsto"; return }
        if state["unlocked"] as? Bool != true {
            statusMenuItem.title = "Locked"
            promptUnlockIfNeeded()
            return
        }
        let sv = state["service"] as? [String: Any] ?? [:]
        let paused = sv["paused"] as? Bool ?? false
        pauseItem.state = paused ? .on : .off
        var text = paused ? "Paused" : "Up to date"
        if let err = sv["last_error"] as? String, !err.isEmpty { text = "Problem: \(err)" }
        else if let t = sv["last_sync_utc"] as? Double {
            let ago = max(0, Int(Date().timeIntervalSince1970 - t))
            text += " · last sync " + (ago < 60 ? "\(ago) s ago" : ago < 3600 ? "\(ago / 60) min ago" : "\(ago / 3600) h ago")
        }
        if let worst = sv["policy_worst"] as? String, worst != "ok" { text += " · policy \(worst.replacingOccurrences(of: "_", with: " "))" }
        statusMenuItem.title = text
        if #available(macOS 13.0, *) { loginItem.state = SMAppService.mainApp.status == .enabled ? .on : .off }
    }

    var prompting = false
    func promptUnlockIfNeeded() {
        if prompting { return }
        prompting = true
        defer { prompting = false }
        let alert = NSAlert()
        alert.messageText = "Unlock Varsto"
        alert.informativeText = "Enter the passphrase of this device. It can be kept in your login keychain so the background service unlocks itself after login."
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        let remember = NSButton(checkboxWithTitle: "Remember in Keychain", target: nil, action: nil)
        remember.state = .on
        let stack = NSStackView(views: [field, remember])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.frame = NSRect(x: 0, y: 0, width: 280, height: 56)
        alert.accessoryView = stack
        alert.addButton(withTitle: "Unlock")
        alert.addButton(withTitle: "Later")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            let pass = field.stringValue
            if let r = client.call("POST", "/api/unlock", body: ["passphrase": pass]), r["ok"] as? Bool == true {
                if remember.state == .on {
                    let sec = Process()
                    sec.executableURL = URL(fileURLWithPath: "/usr/bin/security")
                    sec.arguments = ["add-generic-password", "-U", "-s", "varsto", "-a", home.path, "-w", pass]
                    try? sec.run(); sec.waitUntilExit()
                }
                main.web.reload()
            } else {
                let e = NSAlert(); e.messageText = "Unlock failed"; e.informativeText = "Wrong passphrase?"; e.runModal()
            }
        }
    }

    @objc func openUI() { main.show(url: client.uiURL()) }
    @objc func syncNow() { DispatchQueue.global().async { _ = self.client.call("POST", "/api/sync", body: [:]); DispatchQueue.main.async { self.refresh() } } }
    @objc func togglePause() {
        let paused = pauseItem.state != .on
        _ = client.call("POST", "/api/service/pause", body: ["paused": paused])
        refresh()
    }
    @objc func checkUpdates() {
        updateNote.isHidden = false
        updateNote.title = "Checking…"
        DispatchQueue.global().async {
            let c = self.client.call("GET", "/api/update/check")
            DispatchQueue.main.async {
                NSApp.activate(ignoringOtherApps: true)
                let a = NSAlert()
                guard let c = c else {
                    self.updateNote.title = "Update check failed"
                    a.messageText = "Could not check for updates"
                    a.informativeText = "The background service did not answer. Is it running? Try again in a moment."
                    a.runModal()
                    return
                }
                let current = c["current"] as? String ?? "?"
                let latest = c["latest"] as? String ?? "?"
                if c["available"] as? Bool == true {
                    self.updateNote.title = "Update available: \(latest)"
                    a.messageText = "Varsto \(latest) is available"
                    a.informativeText = "You have \(current). The background service downloads the new version, checks its SHA-256 and restarts itself. This window app is replaced the next time you download Varsto.app; the service keeps working with it meanwhile."
                    a.addButton(withTitle: "Update now")
                    a.addButton(withTitle: "Later")
                    if a.runModal() == .alertFirstButtonReturn {
                        DispatchQueue.global().async {
                            let r = self.client.call("POST", "/api/update", body: [:])
                            DispatchQueue.main.async {
                                let done = NSAlert()
                                if let r = r, r["ok"] as? Bool == true || r["error"] == nil {
                                    self.updateNote.title = "Updated to \(latest); service restarting"
                                    done.messageText = "Update installed"
                                    done.informativeText = "The service restarts with \(latest) in a few seconds."
                                } else {
                                    self.updateNote.title = "Update failed"
                                    done.messageText = "Update failed"
                                    done.informativeText = "\(r?["error"] as? String ?? "no details")"
                                }
                                done.runModal()
                            }
                        }
                    }
                } else {
                    self.updateNote.title = "Up to date (\(current))"
                    a.messageText = "Varsto is up to date"
                    a.informativeText = "Installed: \(current). Latest: \(latest)."
                    a.runModal()
                }
            }
        }
    }
    @objc func installCli() {
        // Symlink the bundled binary into /usr/local/bin so `varsto` works in Terminal.
        let target = "/usr/local/bin/varsto"
        let script = "do shell script \"mkdir -p /usr/local/bin && ln -sf '\(binary.path)' \(target)\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        let a = NSAlert()
        if let error = error {
            a.messageText = "Could not install the command-line tool"
            a.informativeText = "Run this in Terminal instead:\nln -sf '\(binary.path)' \(target)\n\n\(error)"
        } else {
            a.messageText = "Command-line tool installed"
            a.informativeText = "Open Terminal and run: varsto --help\nIt uses the same vault as this app (~/Library/Application Support/Varsto)."
        }
        a.runModal()
    }
    @objc func toggleLogin() {
        if #available(macOS 13.0, *) {
            do {
                if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() } else { try SMAppService.mainApp.register() }
            } catch {
                let e = NSAlert(); e.messageText = "Could not change the login item"; e.informativeText = "\(error)"; e.runModal()
            }
            refresh()
        } else {
            let e = NSAlert(); e.messageText = "Start at login needs macOS 13 or newer"; e.informativeText = "Add Varsto to Login Items in System Settings instead."; e.runModal()
        }
    }
    @objc func quit() { NSApp.terminate(nil) }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        timer?.invalidate()
        process?.terminationHandler = nil
        _ = client.call("POST", "/api/quit", body: [:])
        if let p = process, p.isRunning {
            let deadline = Date().addingTimeInterval(3)
            while p.isRunning && Date() < deadline { usleep(100_000) }
            if p.isRunning { p.terminate() }
        }
        return .terminateNow
    }
}

/// The Services entries declared in Info.plist (NSServices); Finder passes
/// the selected files on a pasteboard.
final class FinderService: NSObject {
    weak var owner: AppDelegate?
    init(owner: AppDelegate) { self.owner = owner }

    @objc func fetchFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        owner?.actOnPaths("fetch", paths(pboard), openAfter: false)
    }

    @objc func freeFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        owner?.actOnPaths("free", paths(pboard), openAfter: false)
    }

    func paths(_ pboard: NSPasteboard) -> [String] {
        let urls = pboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        return urls.map { $0.path }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
