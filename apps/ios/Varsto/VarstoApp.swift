// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Varsto for iOS: runs the Rust service in-process and shows the local interface.
import AVFoundation
import SwiftUI
import UIKit
import WebKit

@main
struct VarstoApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
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
    ]
    let t = texts[en].map { lang == "fi" ? $0.fi : lang == "sv" ? $0.sv : en } ?? en
    return t.replacingOccurrences(of: "{}", with: arg)
}

final class ServiceHost: ObservableObject {
    @Published var url: URL?
    @Published var error: String?

    init() { start() }

    func start() {
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
        if rc != 0 { error = tr("service failed to start ({})", "\(rc)"); return }
        DispatchQueue.global().async {
            for _ in 0..<50 {
                if let c = varsto_url() {
                    let s = String(cString: c); varsto_free(c)
                    DispatchQueue.main.async { self.url = URL(string: s) }
                    if let u = URL(string: s) { VideoThumbs.shared.start(serviceURL: u) }
                    return
                }
                usleep(100_000)
            }
            DispatchQueue.main.async { self.error = tr("service did not start") }
        }
    }
}

struct ContentView: View {
    @StateObject var host = ServiceHost()
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
    }
}

struct WebView: UIViewRepresentable {
    let url: URL
    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let view = WKWebView(frame: .zero, configuration: config)
        // Not wired yet: the page's `window.VarstoAndroid` bridge (open a file in another app,
        // share it, all-files access) has no iOS counterpart. Its place is a WKScriptMessageHandler
        // here that answers openFile/shareFile with UIDocumentInteractionController and
        // UIActivityViewController; without it the page falls back to the download link.
        view.load(URLRequest(url: url))
        return view
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
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
            let gen = AVAssetImageGenerator(asset: AVURLAsset(url: URL(fileURLWithPath: file)))
            gen.appliesPreferredTrackTransform = true
            gen.maximumSize = CGSize(width: 256, height: 256)
            var image: CGImage?
            for t in [1.0, 0.0] {
                if let i = try? gen.copyCGImage(at: CMTime(seconds: t, preferredTimescale: 600), actualTime: nil) { image = i; break }
            }
            guard let cg = image, let jpeg = UIImage(cgImage: cg).jpegData(compressionQuality: 0.8) else { continue }
            _ = call("POST", "/api/thumbnail", ["folder": folder, "path": path, "jpeg": jpeg.base64EncodedString()])
        }
    }
}
