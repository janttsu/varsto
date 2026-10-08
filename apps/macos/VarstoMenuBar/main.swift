// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Varsto menu-bar app for macOS. Starts and supervises the `varsto` background
// service shipped next to this executable, shows its status in the menu bar,
// opens the local interface, and stores the passphrase in the login keychain.
// Built on a Mac with apps/macos/build.sh (needs the Xcode command line tools).

import AppKit
import Foundation
import ServiceManagement

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

    func openURL() -> URL? {
        guard let i = info() else { return nil }
        return URL(string: "http://127.0.0.1:\(i.port)/?token=\(i.token)")
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    var process: Process?
    var client: ServiceClient!
    var home: URL!
    var binary: URL!
    var timer: Timer?
    let statusMenuItem = NSMenuItem(title: "Starting…", action: nil, keyEquivalent: "")
    let pauseItem = NSMenuItem(title: "Pause syncing", action: #selector(togglePause), keyEquivalent: "")
    let updateNote = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let loginItem = NSMenuItem(title: "Start at login", action: #selector(toggleLogin), keyEquivalent: "")

    func applicationDidFinishLaunching(_ notification: Notification) {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        home = support.appendingPathComponent("Varsto")
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        binary = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/varsto")
        client = ServiceClient(home: home)

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = statusItem.button {
            let image = NSImage(systemSymbolName: "lock.icloud", accessibilityDescription: "Varsto") ?? NSImage(named: NSImage.folderName)
            image?.isTemplate = true
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
        menu.addItem(loginItem)
        menu.addItem(withTitle: "Quit Varsto", action: #selector(quit), keyEquivalent: "q")
        for item in menu.items { item.target = self }
        statusItem.menu = menu

        ensureService()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        if ProcessInfo.processInfo.environment["VARSTO_NO_OPEN"] == nil && client.call("GET", "/api/state")?["has_vault"] as? Bool != true {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { self.openUI() }
        }
    }

    func ensureService() {
        if let p = process, p.isRunning { return }
        if client.info() != nil, client.call("GET", "/api/service") != nil { return } // started elsewhere (launch agent)
        let p = Process()
        p.executableURL = binary
        p.arguments = ["--home", home.path, "service", "run", "--port", "0", "--interval", "300"]
        let log = FileHandle(forWritingAtPath: home.appendingPathComponent("service.log").path)
        if log == nil { FileManager.default.createFile(atPath: home.appendingPathComponent("service.log").path, contents: nil) }
        p.standardOutput = FileHandle(forWritingAtPath: home.appendingPathComponent("service.log").path)
        p.standardError = p.standardOutput
        p.terminationHandler = { [weak self] proc in
            // 75 = restart after a self-update; anything else: restart after a pause.
            DispatchQueue.main.asyncAfter(deadline: .now() + (proc.terminationStatus == 75 ? 0.5 : 3)) { self?.ensureService() }
        }
        try? p.run()
        process = p
    }

    func refresh() {
        ensureService()
        guard let state = client.call("GET", "/api/state") else { statusMenuItem.title = "Service starting…"; return }
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
            } else {
                let e = NSAlert(); e.messageText = "Unlock failed"; e.informativeText = "Wrong passphrase?"; e.runModal()
            }
        }
    }

    @objc func openUI() { if let u = client.openURL() { NSWorkspace.shared.open(u) } }
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
            var text = "Update check failed"
            if let c = c {
                if c["available"] as? Bool == true {
                    _ = self.client.call("POST", "/api/update", body: [:])
                    text = "Updating to \(c["latest"] as? String ?? "")… the service restarts itself; quit and reopen Varsto to update this menu-bar app too."
                } else {
                    text = "Up to date (\(c["current"] as? String ?? ""))"
                }
            }
            DispatchQueue.main.async { self.updateNote.title = text }
        }
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
    @objc func quit() {
        _ = client.call("POST", "/api/quit", body: [:])
        process?.terminationHandler = nil
        usleep(300_000)
        process?.terminate()
        NSApp.terminate(nil)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
