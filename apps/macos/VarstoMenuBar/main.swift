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

/// The interface language the user picked in Varsto's window (the web UI
/// writes `<home>/ui-language`): "en", "fi" or "sv". Menus, alerts and the
/// start page follow it; the app re-reads it on every status refresh.
var uiLang = "en"

func readUILang(_ home: URL) -> String {
    let s = (try? String(contentsOf: home.appendingPathComponent("ui-language"), encoding: .utf8))?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return s == "fi" || s == "sv" ? s : "en"
}

/// `en` in the interface language, each `{}` replaced by the next of `args`.
func tr(_ en: String, _ args: String...) -> String {
    var s = en
    if let t = translations[en] { s = uiLang == "fi" ? t.fi : uiLang == "sv" ? t.sv : en }
    for a in args {
        if let r = s.range(of: "{}") { s.replaceSubrange(r, with: a) }
    }
    return s
}

/// English text -> Finnish and Swedish, worded as in the web UI (ui/i18n).
let translations: [String: (fi: String, sv: String)] = [
    "Starting the Varsto service…": ("Varsto-palvelu käynnistyy…", "Varsto-tjänsten startar…"),
    "This window fills in a moment.": ("Ikkuna täyttyy hetken kuluttua.", "Fönstret fylls i om en stund."),
    "OK": ("OK", "OK"),
    "Cancel": ("Peruuta", "Avbryt"),
    "Later": ("Myöhemmin", "Senare"),
    "Starting…": ("Käynnistyy…", "Startar…"),
    "Service starting…": ("Palvelu käynnistyy…", "Tjänsten startar…"),
    "Open Varsto": ("Avaa Varsto", "Öppna Varsto"),
    "Pause syncing": ("Keskeytä synkronointi", "Pausa synkroniseringen"),
    "Install update…": ("Asenna päivitys…", "Installera uppdatering…"),
    "Install Varsto {}…": ("Asenna Varsto {}…", "Installera Varsto {}…"),
    "Install command-line tool…": ("Asenna komentorivityökalu…", "Installera kommandoradsverktyget…"),
    "Start at login": ("Käynnistä kirjauduttaessa", "Starta vid inloggning"),
    "Quit Varsto": ("Lopeta Varsto", "Avsluta Varsto"),
    "About Varsto": ("Tietoja Varstosta", "Om Varsto"),
    "Hide Varsto": ("Kätke Varsto", "Göm Varsto"),
    "Edit": ("Muokkaa", "Redigera"),
    "Cut": ("Leikkaa", "Klipp ut"),
    "Copy": ("Kopioi", "Kopiera"),
    "Paste": ("Liitä", "Klistra in"),
    "Select All": ("Valitse kaikki", "Markera alla"),
    "Window": ("Ikkuna", "Fönster"),
    "Minimize": ("Pienennä", "Minimera"),
    "Could not download": ("Lataus epäonnistui", "Det gick inte att ladda ned"),
    "Could not free up space": ("Tilan vapauttaminen epäonnistui", "Det gick inte att frigöra utrymme"),
    "The Varsto service did not answer. Open Varsto and try again.":
        ("Varsto-palvelu ei vastannut. Avaa Varsto ja yritä uudelleen.",
         "Varsto-tjänsten svarade inte. Öppna Varsto och försök igen."),
    "failed": ("epäonnistui", "misslyckades"),
    "Not set up yet: open Varsto": ("Ei vielä otettu käyttöön: avaa Varsto", "Inte konfigurerat ännu: öppna Varsto"),
    "Locked": ("Lukittu", "Låst"),
    "Paused": ("Keskeytetty", "Pausad"),
    "Up to date": ("Ajan tasalla", "Uppdaterad"),
    "Problem: {}": ("Ongelma: {}", "Problem: {}"),
    "{} · last sync {}": ("{} · viimeisin synkronointi {}", "{} · senaste synkronisering {}"),
    "{} s ago": ("{} s sitten", "för {} s sedan"),
    "{} min ago": ("{} min sitten", "för {} min sedan"),
    "{} h ago": ("{} h sitten", "för {} h sedan"),
    "{} · policy {}": ("{} · säilytyssääntö {}", "{} · lagringsregel {}"),
    "at risk": ("vaarassa", "i riskzonen"),
    "violated": ("rikottu", "bruten"),
    "unknown": ("tuntematon", "okänd"),
    "Unlock Varsto": ("Avaa Varston lukitus", "Lås upp Varsto"),
    "Enter the passphrase of this device. It can be kept in your login keychain so the background service unlocks itself after login.":
        ("Kirjoita tämän laitteen salalause. Sen voi säilyttää kirjautumisavainnipussa, jolloin taustapalvelu avaa lukituksen itse kirjautumisen jälkeen.",
         "Ange lösenfrasen för den här enheten. Den kan sparas i din inloggningsnyckelring så att bakgrundstjänsten låser upp sig själv efter inloggningen."),
    "Remember in Keychain": ("Muista avainnipussa", "Kom ihåg i nyckelringen"),
    "Unlock": ("Avaa lukitus", "Lås upp"),
    "Unlock failed": ("Lukituksen avaaminen epäonnistui", "Det gick inte att låsa upp"),
    "Wrong passphrase?": ("Väärä salalause?", "Fel lösenfras?"),
    "Checking…": ("Tarkistetaan…", "Kontrollerar…"),
    "Update check failed": ("Päivitysten tarkistus epäonnistui", "Uppdateringskontrollen misslyckades"),
    "Could not check for updates": ("Päivityksiä ei voitu tarkistaa", "Det gick inte att söka efter uppdateringar"),
    "The background service did not answer. Is it running? Try again in a moment.":
        ("Taustapalvelu ei vastannut. Onko se käynnissä? Yritä hetken kuluttua uudelleen.",
         "Bakgrundstjänsten svarade inte. Körs den? Försök igen om en stund."),
    "Update available: {}": ("Päivitys saatavilla: {}", "Uppdatering tillgänglig: {}"),
    "Varsto {} is available": ("Varsto {} on saatavilla", "Varsto {} är tillgänglig"),
    "You have {}. Varsto downloads the new version, checks its signature, replaces Varsto.app and starts again.":
        ("Sinulla on {}. Varsto lataa uuden version, tarkistaa sen allekirjoituksen, korvaa Varsto.appin ja käynnistyy uudelleen.",
         "Du har {}. Varsto laddar ned den nya versionen, kontrollerar dess signatur, ersätter Varsto.app och startar om."),
    "Update now": ("Päivitä nyt", "Uppdatera nu"),
    "Updated to {}": ("Päivitetty versioon {}", "Uppdaterad till {}"),
    "Update failed": ("Päivitys epäonnistui", "Uppdateringen misslyckades"),
    "no details": ("ei lisätietoja", "inga detaljer"),
    "You have {}. Download the new disk image and drag Varsto to Applications again; your vault and settings stay as they are.":
        ("Sinulla on {}. Lataa uusi levykuva ja vedä Varsto uudelleen Ohjelmat-kansioon; holvisi ja asetuksesi säilyvät ennallaan.",
         "Du har {}. Ladda ned den nya skivavbilden och dra Varsto till Program igen; ditt valv och dina inställningar förblir som de är."),
    "Open download page": ("Avaa lataussivu", "Öppna nedladdningssidan"),
    "Up to date ({})": ("Ajan tasalla ({})", "Uppdaterad ({})"),
    "Varsto is up to date": ("Varsto on ajan tasalla", "Varsto är uppdaterad"),
    "Installed: {}. Latest: {}.": ("Asennettu: {}. Uusin: {}.", "Installerad: {}. Senaste: {}."),
    "Could not install the command-line tool":
        ("Komentorivityökalun asentaminen epäonnistui", "Det gick inte att installera kommandoradsverktyget"),
    "Run this in Terminal instead:": ("Suorita tämä sen sijaan Päätteessä:", "Kör det här i Terminal i stället:"),
    "Command-line tool installed": ("Komentorivityökalu asennettu", "Kommandoradsverktyget har installerats"),
    "Open Terminal and run: varsto --help\nIt uses the same vault as this app (~/Library/Application Support/Varsto).":
        ("Avaa Pääte ja suorita: varsto --help\nSe käyttää samaa holvia kuin tämä sovellus (~/Library/Application Support/Varsto).",
         "Öppna Terminal och kör: varsto --help\nDet använder samma valv som den här appen (~/Library/Application Support/Varsto)."),
    "Could not change the login item": ("Kirjautumiskohdetta ei voitu muuttaa", "Det gick inte att ändra inloggningsobjektet"),
    "Start at login needs macOS 13 or newer":
        ("Käynnistys kirjauduttaessa vaatii macOS 13:n tai uudemman", "Starta vid inloggning kräver macOS 13 eller senare"),
    "Add Varsto to Login Items in System Settings instead.":
        ("Lisää Varsto sen sijaan Järjestelmäasetusten kirjautumiskohteisiin.",
         "Lägg till Varsto bland inloggningsobjekten i Systeminställningar i stället."),
]

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
            web.loadHTMLString("<html><body style='font-family:-apple-system;padding:2em;color:#334155'><h2>\(tr("Starting the Varsto service…"))</h2><p>\(tr("This window fills in a moment."))</p></body></html>", baseURL: nil)
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
        a.addButton(withTitle: tr("OK")); a.addButton(withTitle: tr("Cancel"))
        completionHandler(a.runModal() == .alertFirstButtonReturn)
    }

    func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) {
        let a = NSAlert(); a.messageText = prompt
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 24))
        field.stringValue = defaultText ?? ""
        a.accessoryView = field
        a.addButton(withTitle: tr("OK")); a.addButton(withTitle: tr("Cancel"))
        completionHandler(a.runModal() == .alertFirstButtonReturn ? field.stringValue : nil)
    }

    // <input type="file"> (Add files, Upload): WebKit asks the app to show the
    // open panel; without this method the button does nothing.
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.canChooseFiles = true
        panel.begin { result in completionHandler(result == .OK ? panel.urls : nil) }
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
    var fastTimer: Timer?
    var updateTimer: Timer?
    // Titles are set by retitle(), in the interface language.
    let updateItem = NSMenuItem(title: "Install update…", action: nil, keyEquivalent: "")
    var latestOffered: String?
    let main = MainWindow()
    let statusMenuItem = NSMenuItem(title: "Starting…", action: nil, keyEquivalent: "")
    let openItem = NSMenuItem(title: "Open Varsto", action: #selector(openUI), keyEquivalent: "o")
    let pauseItem = NSMenuItem(title: "Pause syncing", action: #selector(togglePause), keyEquivalent: "")
    let updateNote = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let cliItem = NSMenuItem(title: "Install command-line tool…", action: #selector(installCli), keyEquivalent: "")
    let loginItem = NSMenuItem(title: "Start at login", action: #selector(toggleLogin), keyEquivalent: "")
    let quitItem = NSMenuItem(title: "Quit Varsto", action: #selector(quit), keyEquivalent: "q")

    func applicationDidFinishLaunching(_ notification: Notification) {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        home = support.appendingPathComponent("Varsto")
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        binary = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/varsto")
        client = ServiceClient(home: home)
        uiLang = readUILang(home)

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
        menu.addItem(openItem)
        menu.addItem(pauseItem)
        // Shown only when a newer version exists (checked by itself).
        updateItem.action = #selector(checkUpdates)
        updateItem.isHidden = true
        menu.addItem(updateItem)
        updateNote.isEnabled = false
        updateNote.isHidden = true
        menu.addItem(updateNote)
        menu.addItem(.separator())
        menu.addItem(cliItem)
        menu.addItem(loginItem)
        menu.addItem(quitItem)
        for item in menu.items { item.target = self }
        statusItem.menu = menu
        retitle()

        NSApp.servicesProvider = FinderService(owner: self)
        NSUpdateDynamicServices()
        ensureService()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        // The menu follows the window quickly too (a reset, an unlock, a new vault).
        fastTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            if self?.main.window?.isVisible == true { self?.refresh() }
        }
        installCliQuietly()
        // Updates are looked for without asking: shortly after start and every
        // six hours. A new version is offered once; the menu keeps the item.
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in self?.autoCheckUpdates() }
        updateTimer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in self?.autoCheckUpdates() }
        if ProcessInfo.processInfo.environment["VARSTO_NO_OPEN"] == nil {
            // Not when Finder started us to open a placeholder.
            // Finder may hand over a Download or Free request just after starting
            // us; wait a moment so that such a start opens no window.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { if !self.launchedForFiles { self.openUI() } }
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
        let title = action == "fetch" ? tr("Could not download") : tr("Could not free up space")
        guard let r = r else { alert(title, tr("The Varsto service did not answer. Open Varsto and try again.")); return }
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
                failed.append("\((p as NSString).lastPathComponent): \(x["error"] as? String ?? tr("failed"))")
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

    /// The application menu; built again when the interface language changes.
    func buildMainMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem(); mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: tr("About Varsto"), action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: tr("Hide Varsto"), action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let appQuit = appMenu.addItem(withTitle: tr("Quit Varsto"), action: #selector(quit), keyEquivalent: "q")
        appQuit.target = self
        appItem.submenu = appMenu
        let editItem = NSMenuItem(); mainMenu.addItem(editItem)
        let edit = NSMenu(title: tr("Edit"))
        edit.addItem(withTitle: tr("Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: tr("Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: tr("Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: tr("Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        let windowItem = NSMenuItem(); mainMenu.addItem(windowItem)
        let win = NSMenu(title: tr("Window"))
        let showItem = win.addItem(withTitle: "Varsto", action: #selector(openUI), keyEquivalent: "1")
        showItem.target = self
        win.addItem(withTitle: tr("Minimize"), action: #selector(NSWindow.miniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = win
        NSApp.mainMenu = mainMenu
    }

    /// Titles of the menu-bar menu in the interface language.
    func retitle() {
        statusMenuItem.title = tr("Starting…")
        openItem.title = tr("Open Varsto")
        pauseItem.title = tr("Pause syncing")
        updateItem.title = latestOffered.map { tr("Install Varsto {}…", $0) } ?? tr("Install update…")
        cliItem.title = tr("Install command-line tool…")
        loginItem.title = tr("Start at login")
        quitItem.title = tr("Quit Varsto")
    }

    var agentTried = false
    func ensureService() {
        if let p = process, p.isRunning { return }
        if client.info() != nil, client.call("GET", "/api/service") != nil { return } // started elsewhere (launch agent)
        // Background sync runs as a launch agent, so it keeps going when this
        // window app quits and is the same service the command line uses.
        // Only if that cannot be set up does the app run the service itself.
        if !agentTried {
            agentTried = true
            let off = home.appendingPathComponent("service-off")
            if !FileManager.default.fileExists(atPath: off.path) {
                // Installed earlier or not: (re)load it, pointing at this app.
                let i = Process()
                i.executableURL = binary
                i.arguments = ["--home", home.path, "service", "install", "--interval", "300"]
                i.standardOutput = FileHandle.nullDevice
                i.standardError = FileHandle.nullDevice
                if (try? i.run()) != nil {
                    i.waitUntilExit()
                    if i.terminationStatus == 0 { return }
                }
            }
        }
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

    /// The version this process was started from; when the bundle on disk
    /// changes (an update from the menu or from `varsto update`), start the
    /// new app and quit this one.
    let startedVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
    var relaunching = false
    func relaunchIfUpdated() {
        if relaunching { return }
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Info.plist")
        guard let d = NSDictionary(contentsOf: plist),
              let v = d["CFBundleShortVersionString"] as? String,
              let started = startedVersion, v != started else { return }
        relaunching = true
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = ["-n", Bundle.main.bundleURL.path]
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            NSApp.terminate(nil)
        }
        // Started by launchd after this process exits: open waits for nothing.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { try? open.run() }
    }

    var refreshing = false
    func refresh() {
        relaunchIfUpdated()
        if relaunching { return }
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
        // A language picked in the window applies to the menus right away.
        let lang = readUILang(home)
        if lang != uiLang { uiLang = lang; buildMainMenu(); retitle() }
        guard let state = state else { statusMenuItem.title = tr("Service starting…"); return }
        if main.window?.isVisible == true, main.loadedURL.isEmpty { main.show(url: client.uiURL()) }
        if state["has_vault"] as? Bool != true {
            // No vault (first start, or just reset): nothing of the old one stays.
            statusMenuItem.title = tr("Not set up yet: open Varsto")
            pauseItem.state = .off
            updateNote.isHidden = true
            return
        }
        if state["unlocked"] as? Bool != true {
            statusMenuItem.title = tr("Locked")
            promptUnlockIfNeeded()
            return
        }
        let sv = state["service"] as? [String: Any] ?? [:]
        let paused = sv["paused"] as? Bool ?? false
        pauseItem.state = paused ? .on : .off
        var text = paused ? tr("Paused") : tr("Up to date")
        if let err = sv["last_error"] as? String, !err.isEmpty { text = tr("Problem: {}", err) }
        else if let t = sv["last_sync_utc"] as? Double {
            let ago = max(0, Int(Date().timeIntervalSince1970 - t))
            text = tr("{} · last sync {}", text, ago < 60 ? tr("{} s ago", "\(ago)") : ago < 3600 ? tr("{} min ago", "\(ago / 60)") : tr("{} h ago", "\(ago / 3600)"))
        }
        if let worst = sv["policy_worst"] as? String, worst != "ok" { text = tr("{} · policy {}", text, tr(worst.replacingOccurrences(of: "_", with: " "))) }
        statusMenuItem.title = text
        if #available(macOS 13.0, *) { loginItem.state = SMAppService.mainApp.status == .enabled ? .on : .off }
    }

    var prompting = false
    func promptUnlockIfNeeded() {
        if prompting { return }
        prompting = true
        defer { prompting = false }
        let alert = NSAlert()
        alert.messageText = tr("Unlock Varsto")
        alert.informativeText = tr("Enter the passphrase of this device. It can be kept in your login keychain so the background service unlocks itself after login.")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        let remember = NSButton(checkboxWithTitle: tr("Remember in Keychain"), target: nil, action: nil)
        remember.state = .on
        let stack = NSStackView(views: [field, remember])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.frame = NSRect(x: 0, y: 0, width: 280, height: 56)
        alert.accessoryView = stack
        alert.addButton(withTitle: tr("Unlock"))
        alert.addButton(withTitle: tr("Later"))
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
                let e = NSAlert(); e.messageText = tr("Unlock failed"); e.informativeText = tr("Wrong passphrase?"); e.runModal()
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
    func autoCheckUpdates() {
        DispatchQueue.global().async {
            let c = self.client.call("GET", "/api/update/check")
            DispatchQueue.main.async {
                guard let c = c, c["newer"] as? Bool == true, let latest = c["latest"] as? String else {
                    self.updateItem.isHidden = true
                    return
                }
                self.latestOffered = latest
                self.updateItem.title = tr("Install Varsto {}…", latest)
                self.updateItem.isHidden = false
                if UserDefaults.standard.string(forKey: "offeredUpdate") != latest {
                    UserDefaults.standard.set(latest, forKey: "offeredUpdate")
                    self.checkUpdates()
                }
            }
        }
    }

    @objc func checkUpdates() {
        updateNote.isHidden = false
        updateNote.title = tr("Checking…")
        DispatchQueue.global().async {
            let c = self.client.call("GET", "/api/update/check")
            DispatchQueue.main.async {
                NSApp.activate(ignoringOtherApps: true)
                let a = NSAlert()
                guard let c = c else {
                    self.updateNote.title = tr("Update check failed")
                    a.messageText = tr("Could not check for updates")
                    a.informativeText = tr("The background service did not answer. Is it running? Try again in a moment.")
                    a.runModal()
                    return
                }
                let current = c["current"] as? String ?? "?"
                let latest = c["latest"] as? String ?? "?"
                if c["available"] as? Bool == true {
                    self.updateNote.title = tr("Update available: {}", latest)
                    a.messageText = tr("Varsto {} is available", latest)
                    a.informativeText = tr("You have {}. Varsto downloads the new version, checks its signature, replaces Varsto.app and starts again.", current)
                    a.addButton(withTitle: tr("Update now"))
                    a.addButton(withTitle: tr("Later"))
                    if a.runModal() == .alertFirstButtonReturn {
                        DispatchQueue.global().async {
                            let r = self.client.call("POST", "/api/update", body: [:])
                            DispatchQueue.main.async {
                                let done = NSAlert()
                                if let r = r, r["ok"] as? Bool == true || r["error"] == nil {
                                    // The bundle was replaced: start the new app and leave.
                                    self.updateNote.title = tr("Updated to {}", latest)
                                    self.relaunchIfUpdated()
                                    return
                                } else {
                                    self.updateNote.title = tr("Update failed")
                                    done.messageText = tr("Update failed")
                                    done.informativeText = "\(r?["error"] as? String ?? tr("no details"))"
                                }
                                done.runModal()
                            }
                        }
                    }
                } else if c["newer"] as? Bool == true {
                    // The app bundle is replaced by downloading the new disk image.
                    let page = c["download_page"] as? String ?? "https://varsto.net/downloads/"
                    self.updateNote.title = tr("Update available: {}", latest)
                    a.messageText = tr("Varsto {} is available", latest)
                    a.informativeText = tr("You have {}. Download the new disk image and drag Varsto to Applications again; your vault and settings stay as they are.", current)
                    a.addButton(withTitle: tr("Open download page"))
                    a.addButton(withTitle: tr("Later"))
                    if a.runModal() == .alertFirstButtonReturn, let url = URL(string: page) {
                        NSWorkspace.shared.open(url)
                    }
                } else {
                    self.updateNote.title = tr("Up to date ({})", current)
                    a.messageText = tr("Varsto is up to date")
                    a.informativeText = tr("Installed: {}. Latest: {}.", current, latest)
                    a.runModal()
                }
            }
        }
    }
    /// The command-line tool by default: a link in the first directory of the
    /// usual PATH that this user can write (/opt/homebrew/bin, /usr/local/bin),
    /// pointing into this app, so an updated app is an updated command line.
    /// A link to another copy, or an old standalone binary, is replaced. When
    /// no such directory is writable, the menu item asks for an administrator.
    func installCliQuietly() {
        let fm = FileManager.default
        for dir in ["/opt/homebrew/bin", "/usr/local/bin"] {
            let target = dir + "/varsto"
            if let dest = try? fm.destinationOfSymbolicLink(atPath: target), dest == binary.path { return }
            guard fm.isWritableFile(atPath: dir) else { continue }
            try? fm.removeItem(atPath: target)
            if (try? fm.createSymbolicLink(atPath: target, withDestinationPath: binary.path)) != nil { return }
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
            a.messageText = tr("Could not install the command-line tool")
            a.informativeText = tr("Run this in Terminal instead:") + "\nln -sf '\(binary.path)' \(target)\n\n\(error)"
        } else {
            a.messageText = tr("Command-line tool installed")
            a.informativeText = tr("Open Terminal and run: varsto --help\nIt uses the same vault as this app (~/Library/Application Support/Varsto).")
        }
        a.runModal()
    }
    @objc func toggleLogin() {
        if #available(macOS 13.0, *) {
            do {
                if SMAppService.mainApp.status == .enabled { try SMAppService.mainApp.unregister() } else { try SMAppService.mainApp.register() }
            } catch {
                let e = NSAlert(); e.messageText = tr("Could not change the login item"); e.informativeText = "\(error)"; e.runModal()
            }
            refresh()
        } else {
            let e = NSAlert(); e.messageText = tr("Start at login needs macOS 13 or newer"); e.informativeText = tr("Add Varsto to Login Items in System Settings instead."); e.runModal()
        }
    }
    @objc func quit() { NSApp.terminate(nil) }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        timer?.invalidate()
        fastTimer?.invalidate()
        updateTimer?.invalidate()
        process?.terminationHandler = nil
        // A launch agent keeps syncing after the app quits; only a service
        // this app started itself is stopped with it.
        if let p = process, p.isRunning {
            _ = client.call("POST", "/api/quit", body: [:])
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

    // Download / Free up space from Finder happen in the background: Varsto's
    // window does not open for them (only a failure shows a dialog).
    @objc func fetchFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        owner?.launchedForFiles = true
        owner?.actOnPaths("fetch", paths(pboard), openAfter: false)
    }

    @objc func freeFiles(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        owner?.launchedForFiles = true
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
