// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Varsto for iOS: runs the Rust service in-process and shows the local interface.
import SwiftUI
import WebKit

@main
struct VarstoApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
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
        let rc = home.path.withCString { varsto_start($0, 0) }
        if rc != 0 { error = "service failed to start (\(rc))"; return }
        DispatchQueue.global().async {
            for _ in 0..<50 {
                if let c = varsto_url() {
                    let s = String(cString: c); varsto_free(c)
                    DispatchQueue.main.async { self.url = URL(string: s) }
                    return
                }
                usleep(100_000)
            }
            DispatchQueue.main.async { self.error = "service did not start" }
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
                ProgressView("Starting Varsto…")
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
        view.load(URLRequest(url: url))
        return view
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
