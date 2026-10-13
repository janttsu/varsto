// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Varsto for iOS: runs the Rust service in-process and shows the local interface.
import AVFoundation
import SwiftUI
import UIKit
import WebKit

@main
struct VarstoApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup { ContentView() }
            .onChange(of: scenePhase) { phase in
                switch phase {
                case .active:
                    CameraUpload.shared.requestScan(1)
                case .background:
                    // Finish an upload that is under way, then let iOS run the rest later.
                    CameraUpload.shared.finishInBackground()
                    Background.schedule()
                default:
                    break
                }
            }
    }
}

/// Starts the service and camera upload at launch, also when iOS launches the
/// app in the background for one of its background tasks (no window then).
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // Background task handlers must be registered before launching ends.
        Background.register()
        ServiceHost.shared.start()
        CameraUpload.shared.start()
        return true
    }
}

/// `en` in the interface language picked in the web UI (`<home>/ui-language`:
/// "en", "fi" or "sv"), with `{}` replaced by `arg`.
func tr(_ en: String, _ arg: String = "") -> String {
    let home = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Varsto")
    let lang = (try? String(contentsOf: home.appendingPathComponent("ui-language"), encoding: .utf8))?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? "en"
    let texts: [String: (fi: String, sv: String)] = [
        "Starting Varsto…": ("Varsto käynnistyy…", "Varsto startar…"),
        "service failed to start ({})": ("palvelun käynnistys epäonnistui ({})", "tjänsten kunde inte startas ({})"),
        "service did not start": ("palvelu ei käynnistynyt", "tjänsten startade inte"),
        // Viewer
        "Done": ("Valmis", "Klar"),
        "Share": ("Jaa", "Dela"),
        "Cancel": ("Peruuta", "Avbryt"),
        "Share a decrypted copy?": ("Jaetaanko purettu kopio?", "Dela en dekrypterad kopia?"),
        "Varsto makes a decrypted copy of {} for the app you choose and removes its own copy afterwards; the other app may keep its own.":
            ("Varsto tekee tiedostosta {} puretun kopion valitsemallesi sovellukselle ja poistaa oman kopionsa sen jälkeen; toinen sovellus voi säilyttää omansa.",
             "Varsto gör en dekrypterad kopia av {} åt appen du väljer och tar bort sin egen kopia efteråt; den andra appen kan behålla sin."),
        "Could not share the file: {}": ("Tiedostoa ei voitu jakaa: {}", "Filen kunde inte delas: {}"),
        "This file cannot be shown here.": ("Tätä tiedostoa ei voi näyttää tässä.", "Den här filen kan inte visas här."),
        "This kind of file cannot be shown here. Share hands a decrypted copy to another app.":
            ("Tämänlaista tiedostoa ei voi näyttää tässä. Jaa antaa puretun kopion toiselle sovellukselle.",
             "Den här typen av fil kan inte visas här. Dela ger en dekrypterad kopia till en annan app."),
    ]
    let t = texts[en].map { lang == "fi" ? $0.fi : lang == "sv" ? $0.sv : en } ?? en
    return t.replacingOccurrences(of: "{}", with: arg)
}

/// The in-process service. One per app process: started at launch (also for
/// background tasks) and kept running for as long as iOS keeps the process.
final class ServiceHost: ObservableObject {
    static let shared = ServiceHost()
    @Published var url: URL?
    @Published var error: String?
    private let lock = NSLock()
    private var started = false
    private var ready: URL?

    /// The start URL (`http://127.0.0.1:PORT/?token=…`) once the service runs; any thread.
    var serviceURL: URL? {
        lock.lock(); defer { lock.unlock() }
        return ready
    }

    func start() {
        lock.lock()
        if started { lock.unlock(); return }
        started = true
        lock.unlock()
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let home = support.appendingPathComponent("Varsto")
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        // Keep the vault out of iCloud backups: keys and ledger belong to this device only.
        var values = URLResourceValues(); values.isExcludedFromBackup = true
        var h = home; try? h.setResourceValues(values)
        // Shown to the user's other devices in their device list.
        setenv("VARSTO_OS", "iOS", 1)
        setenv("VARSTO_OS_VERSION", UIDevice.current.systemVersion, 1)
        setenv("VARSTO_DEVICE_MODEL", UIDevice.current.model, 1)
        let rc = home.path.withCString { varsto_start($0, 0) }
        if rc != 0 {
            let e = tr("service failed to start ({})", "\(rc)")
            DispatchQueue.main.async { self.error = e }
            return
        }
        DispatchQueue.global().async {
            for _ in 0..<50 {
                if let c = varsto_url() {
                    let s = String(cString: c); varsto_free(c)
                    if let u = URL(string: s) {
                        self.lock.lock(); self.ready = u; self.lock.unlock()
                        VideoThumbs.shared.start(serviceURL: u)
                    }
                    DispatchQueue.main.async { self.url = URL(string: s) }
                    return
                }
                usleep(100_000)
            }
            DispatchQueue.main.async { self.error = tr("service did not start") }
        }
    }

    /// Calls `done` (on a background queue) with the start URL once the service
    /// runs, or with nil after `timeout` seconds.
    func whenReady(timeout: TimeInterval, _ done: @escaping (URL?) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            let until = Date().addingTimeInterval(timeout)
            while Date() < until {
                if let u = self.serviceURL { done(u); return }
                usleep(200_000)
            }
            done(self.serviceURL)
        }
    }
}

struct ContentView: View {
    @ObservedObject var host = ServiceHost.shared
    var body: some View {
        Group {
            if let url = host.url {
                WebView(url: url).ignoresSafeArea(edges: .bottom)
            } else if let e = host.error {
                VStack(spacing: 12) { Text("Varsto").font(.largeTitle.bold()); Text(e).foregroundColor(.secondary) }
            } else {
                ProgressView(tr("Starting Varsto…"))
            }
        }
        .onAppear { host.start() }
    }
}

struct WebView: UIViewRepresentable {
    let url: URL

    func makeCoordinator() -> WebBridge { WebBridge() }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        // The page's bridges: camera upload settings (`window.VarstoIOS`, the same
        // methods as Android's `window.VarstoAndroid`) and the native viewer.
        let content = config.userContentController
        content.add(context.coordinator, name: "varstoCamera")
        content.add(context.coordinator, name: "varstoViewer")
        context.coordinator.installScript(content)
        let view = WKWebView(frame: .zero, configuration: config)
        context.coordinator.web = view
        // Not wired yet: Android's openFile/shareFile (open a file of the list in another
        // app) have no iOS counterpart in the file list; without them the page falls back
        // to the download link. The native viewer has its own Share button.
        view.load(URLRequest(url: url))
        return view
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {}
}

/// Answers the page's messages and keeps its copy of the camera upload state current.
final class WebBridge: NSObject, WKScriptMessageHandler {
    weak var web: WKWebView?
    private var lastState = ""

    override init() {
        super.init()
        CameraUpload.shared.onChange = { [weak self] in self?.cameraChanged() }
        NotificationCenter.default.addObserver(self, selector: #selector(resumed),
                                               name: UIApplication.didBecomeActiveNotification, object: nil)
    }

    /// The camera upload state as JSON (see CameraUpload.Settings.json).
    private func stateJSON() -> String {
        let data = (try? JSONSerialization.data(withJSONObject: CameraUpload.Settings.json())) ?? Data("{}".utf8)
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    /// `window.VarstoIOS`, defined before app.js runs. The page calls its methods
    /// synchronously, as on Android, so it answers from a copy of the state that
    /// this side replaces on every change; changes go back as messages.
    func installScript(_ content: WKUserContentController) {
        let state = stateJSON()
        lastState = state
        let source = """
        (function () {
          var post = function (m) { window.webkit.messageHandlers.varstoCamera.postMessage(m); };
          var state = \(state);
          window.VarstoIOS = {
            cameraUpload: function () { return JSON.stringify(state); },
            setCameraUpload: function (json) {
              var s = JSON.parse(json);
              if (s.enabled && !state.enabled) { state.since = Math.floor(Date.now() / 1000); }
              ["enabled", "folder", "wifi_only", "charging_only", "screenshots"].forEach(function (k) { state[k] = s[k]; });
              state.folder = String(state.folder || "").trim();
              post({ action: "set", settings: s });
            },
            hasMediaAccess: function () { return !!state.permission; },
            requestMediaAccess: function () { post({ action: "requestAccess" }); },
            openAppSettings: function () { post({ action: "openSettings" }); },
            update: function (s, quiet) { state = s; if (!quiet && window.varstoCameraChanged) { window.varstoCameraChanged(); } }
          };
        })();
        """
        content.removeAllUserScripts()
        content.addUserScript(WKUserScript(source: source, injectionTime: .atDocumentStart, forMainFrameOnly: true))
    }

    private func cameraChanged() {
        let state = stateJSON()
        if state == lastState { return }
        lastState = state
        guard let web = web else { return }
        // A reload (the language picker reloads the page) starts from the current state.
        installScript(web.configuration.userContentController)
        web.evaluateJavaScript("window.VarstoIOS && window.VarstoIOS.update(\(state))", completionHandler: nil)
    }

    @objc private func resumed() {
        web?.evaluateJavaScript("window.varstoResumed && window.varstoResumed()", completionHandler: nil)
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let body = message.body as? [String: Any] else { return }
        switch message.name {
        case "varstoCamera": camera(body)
        case "varstoViewer": openViewer(body)
        default: break
        }
    }

    private func camera(_ body: [String: Any]) {
        switch body["action"] as? String {
        case "set":
            guard let settings = body["settings"] as? [String: Any] else { return }
            CameraUpload.Settings.save(settings)
            CameraUpload.shared.settingsChanged()
        case "requestAccess":
            CameraUpload.shared.requestAccess { [weak self] granted, blocked in
                guard let self = self else { return }
                let state = self.stateJSON()
                self.lastState = state
                if let web = self.web { self.installScript(web.configuration.userContentController) }
                // The new state first, quietly: the page goes on with the choices it is in the middle of.
                self.web?.evaluateJavaScript(
                    "window.VarstoIOS && window.VarstoIOS.update(\(state), true); window.varstoMediaAccess && window.varstoMediaAccess(\(granted), \(blocked))",
                    completionHandler: nil)
            }
        case "openSettings":
            if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
        default:
            break
        }
    }

    /// `{folder, index, items: [{path, name, kind, size, view}]}` from the page's openViewer;
    /// `view` is the token-less /api/view path, the token is added here.
    private func openViewer(_ body: [String: Any]) {
        guard let list = body["items"] as? [[String: Any]], !list.isEmpty,
              let start = ServiceHost.shared.serviceURL, let api = LocalAPI(url: start) else { return }
        let items: [ViewerItem] = list.compactMap { d in
            guard let path = d["path"] as? String, let view = d["view"] as? String,
                  let url = URL(string: api.base + view + "&token=" + api.token) else { return nil }
            let size = (d["size"] as? NSNumber)?.int64Value ?? 0
            return ViewerItem(path: path, name: d["name"] as? String ?? path, kind: d["kind"] as? String ?? "", size: size, url: url)
        }
        guard !items.isEmpty, var top = web?.window?.rootViewController else { return }
        while let next = top.presentedViewController { top = next }
        let index = min(max((body["index"] as? Int) ?? 0, 0), items.count - 1)
        let viewer = MediaViewerController(items: items, index: index)
        viewer.modalPresentationStyle = .overFullScreen
        viewer.modalTransitionStyle = .crossDissolve
        viewer.modalPresentationCapturesStatusBarAppearance = true
        top.present(viewer, animated: true)
    }
}

/// Video thumbnails: the service has no ffmpeg on a phone, so it lists the
/// videos in plain folders that have none, and this makes a frame with
/// AVFoundation and hands it back to be encrypted and stored.
final class VideoThumbs {
    static let shared = VideoThumbs()
    private var timer: Timer?
    private var base = ""
    private var token = ""

    func start(serviceURL: URL) {
        guard timer == nil, var c = URLComponents(url: serviceURL, resolvingAgainstBaseURL: false) else { return }
        token = c.queryItems?.first(where: { $0.name == "token" })?.value ?? ""
        c.query = nil; c.path = ""
        base = c.string ?? ""
        DispatchQueue.main.async {
            self.timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
                DispatchQueue.global(qos: .utility).async { self?.round() }
            }
        }
    }

    private func call(_ method: String, _ path: String, _ body: [String: Any]?) -> [String: Any]? {
        guard let url = URL(string: base + path) else { return nil }
        var req = URLRequest(url: url, timeoutInterval: 120)
        req.httpMethod = method
        req.setValue(token, forHTTPHeaderField: "X-Varsto-Token")
        if let body = body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        var out: [String: Any]?
        let done = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { data, resp, _ in
            if let data = data, (resp as? HTTPURLResponse)?.statusCode == 200 {
                out = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            }
            done.signal()
        }.resume()
        done.wait()
        return out
    }

    private func round() {
        guard let list = call("GET", "/api/thumbnails/wanted", nil)?["videos"] as? [[String: Any]] else { return }
        for v in list {
            guard let file = v["file"] as? String, let folder = v["folder"] as? String,
                  let path = v["path"] as? String else { continue }
            guard let jpeg = Self.frame(of: URL(fileURLWithPath: file)) else { continue }
            _ = call("POST", "/api/thumbnail", ["folder": folder, "path": path, "jpeg": jpeg.base64EncodedString()])
        }
    }

    /// A JPEG of a frame near the start of the video at `file`, at most 256 pixels wide or high.
    static func frame(of file: URL) -> Data? {
        let gen = AVAssetImageGenerator(asset: AVURLAsset(url: file))
        gen.appliesPreferredTrackTransform = true
        gen.maximumSize = CGSize(width: 256, height: 256)
        var image: CGImage?
        for t in [1.0, 0.0] {
            if let i = try? gen.copyCGImage(at: CMTime(seconds: t, preferredTimescale: 600), actualTime: nil) { image = i; break }
        }
        guard let cg = image else { return nil }
        return UIImage(cgImage: cg).jpegData(compressionQuality: 0.8)
    }
}
