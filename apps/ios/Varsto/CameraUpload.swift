// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Camera upload: new photos and videos in the photo library go into one Varsto
// folder, in YYYY/MM subfolders named after the capture date, through the local
// service (`POST /api/upload`), so they are encrypted and pushed like any other
// file. The same settings, status messages and service calls as the Android
// app (apps/android/.../CameraUpload.kt).
import AVFoundation
import Foundation
import Network
import Photos
import UIKit

/// Scans run one at a time on a serial queue. While the app runs, a change in
/// the photo library, the network or the charger starts one; in the background
/// iOS decides when (see Background), and a 30-minute timer retries what had
/// to wait while the app stays in the foreground.
///
/// Every uploaded item is remembered by its local identifier and creation date
/// in `camera-upload-done.txt`, so nothing is uploaded twice, also across
/// restarts. Originals are only read, never changed or deleted.
final class CameraUpload: NSObject, PHPhotoLibraryChangeObserver {
    static let shared = CameraUpload()
    /// Same limit as the service's /api/upload (which streams, nothing is held in memory).
    static let maxUpload: Int64 = 16 << 30

    /// Called on the main thread when the settings or the status may have changed.
    var onChange: (() -> Void)?

    private let queue = DispatchQueue(label: "camera-upload", qos: .utility)
    private let monitor = NWPathMonitor()
    private let lock = NSLock()
    // Guarded by `lock`:
    private var started = false
    private var observing = false
    private var path: NWPath?
    private var charging = false
    private var pending: DispatchWorkItem?
    private var cancelled = false
    private var currentTask: URLSessionTask?
    private var currentRequest: PHAssetResourceDataRequestID?
    private var progressText: String?
    // Only touched on `queue`:
    private var done: Set<String>?
    // Main thread:
    private var timer: Timer?

    private static var supportDir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }
    private let doneFile = CameraUpload.supportDir.appendingPathComponent("camera-upload-done.txt")

    // MARK: Triggers

    func start() {
        lock.lock()
        if started { lock.unlock(); return }
        started = true
        lock.unlock()
        monitor.pathUpdateHandler = { [weak self] p in
            guard let self = self else { return }
            self.lock.lock(); self.path = p; self.lock.unlock()
            self.requestScan(5)
        }
        monitor.start(queue: DispatchQueue(label: "camera-upload-network"))
        DispatchQueue.main.async {
            UIDevice.current.isBatteryMonitoringEnabled = true
            self.powerChanged()
            NotificationCenter.default.addObserver(self, selector: #selector(self.powerChanged),
                                                   name: UIDevice.batteryStateDidChangeNotification, object: nil)
            self.timer = Timer.scheduledTimer(withTimeInterval: 30 * 60, repeats: true) { [weak self] _ in
                self?.requestScan(0)
            }
        }
        observeLibrary()
        requestScan(10)
    }

    @objc private func powerChanged() {
        let state = UIDevice.current.batteryState
        lock.lock(); charging = state == .charging || state == .full; lock.unlock()
        requestScan(1)
    }

    /// Changes in the photo library while the app runs (only once access was given:
    /// registering earlier would make iOS ask for access on its own).
    private func observeLibrary() {
        guard Self.hasPermission else { return }
        lock.lock()
        let first = !observing
        observing = true
        lock.unlock()
        if first { PHPhotoLibrary.shared().register(self) }
    }

    func photoLibraryDidChange(_ changeInstance: PHChange) {
        requestScan(3)
    }

    /// The interface changed the settings: look now, and (re)plan the background task.
    func settingsChanged() {
        requestScan(0.5)
        Background.schedule()
        notifyChange()
    }

    /// Scan after `delay` seconds; bursts of changes collapse into one scan.
    func requestScan(_ delay: TimeInterval) {
        let item = DispatchWorkItem { [weak self] in self?.scanSafely() }
        lock.lock(); pending?.cancel(); pending = item; lock.unlock()
        queue.asyncAfter(deadline: .now() + delay, execute: item)
    }

    /// Scan now (after a scan that is under way) and call `completion` afterwards; for background tasks.
    func runNow(_ completion: @escaping () -> Void) {
        lock.lock(); pending?.cancel(); pending = nil; lock.unlock()
        queue.async { [weak self] in
            self?.scanSafely()
            completion()
        }
    }

    /// Stop the scan under way (a background task ran out of time); what was uploaded stays done.
    func cancelRunning() {
        lock.lock()
        cancelled = true
        let task = currentTask
        let request = currentRequest
        lock.unlock()
        task?.cancel()
        if let r = request { PHAssetResourceManager.default().cancelDataRequest(r) }
    }

    /// The app went to the background: ask iOS for the time to finish the scan under way.
    func finishInBackground() {
        var id = UIBackgroundTaskIdentifier.invalid
        id = UIApplication.shared.beginBackgroundTask(withName: "camera-upload") { [weak self] in
            self?.cancelRunning()
            if id != .invalid { UIApplication.shared.endBackgroundTask(id); id = .invalid }
        }
        queue.async {
            DispatchQueue.main.async {
                if id != .invalid { UIApplication.shared.endBackgroundTask(id); id = .invalid }
            }
        }
    }

    // MARK: Permission

    static var hasPermission: Bool {
        let s = PHPhotoLibrary.authorizationStatus(for: .readWrite)
        return s == .authorized || s == .limited
    }

    /// Ask for read access to the photo library. `done(granted, blocked)` runs on the main
    /// thread; `blocked` means iOS showed no question because access was refused before,
    /// so only the Settings app can give it now.
    func requestAccess(_ done: @escaping (Bool, Bool) -> Void) {
        let before = PHPhotoLibrary.authorizationStatus(for: .readWrite)
        if before == .denied || before == .restricted {
            DispatchQueue.main.async { done(false, true) }
            return
        }
        PHPhotoLibrary.requestAuthorization(for: .readWrite) { status in
            let granted = status == .authorized || status == .limited
            if granted {
                self.observeLibrary()
                self.requestScan(0.5)
            }
            DispatchQueue.main.async { done(granted, false) }
        }
    }

    // MARK: Scan

    private struct Cancelled: Error {}

    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private func checkCancelled() throws {
        lock.lock(); let c = cancelled; lock.unlock()
        if c { throw Cancelled() }
    }

    private func scanSafely() {
        lock.lock(); cancelled = false; lock.unlock()
        do {
            try scan()
        } catch {
            lock.lock(); let stopped = cancelled; lock.unlock()
            // Out of background time (or a cancelled transfer): the next scan goes on from here.
            if !(error is Cancelled) && !stopped { Settings.status("error", error.localizedDescription) }
        }
        progress(nil)
    }

    private func scan() throws {
        let s = Settings.load()
        if !s.enabled || s.folder.isEmpty { return }
        if !Self.hasPermission { return Settings.status("waiting", "Allow access to photos and videos") }
        observeLibrary()
        if s.wifiOnly && !onWifi() { return Settings.status("waiting", "Waiting for Wi-Fi") }
        if s.chargingOnly && !isCharging() { return Settings.status("waiting", "Waiting for the charger") }
        let items = newItems(s)
        if items.isEmpty { return Settings.status("idle", limitedNote()) }
        guard let api = LocalAPI.connect() else { return Settings.status("waiting", "Waiting for the Varsto service") }
        let state = try api.object("/api/state")
        if (state["unlocked"] as? Bool) != true { return Settings.status("waiting", "Waiting for Varsto to be unlocked") }
        var found = false
        var encrypted = false
        for f in try api.array("/api/folders") where (f["name"] as? String) == s.folder && f["path"] is String {
            found = true
            encrypted = !((f["plain"] as? Bool) ?? true)
        }
        if !found { return Settings.status("error", "Folder \(s.folder) is not on this phone") }
        // Paths already in the folder, with their sizes: never overwrite a file.
        var existing: [String: Int64] = [:]
        for f in try api.array("/api/files?folder=" + LocalAPI.enc(s.folder)) {
            if let p = f["path"] as? String { existing[p] = (f["size"] as? NSNumber)?.int64Value ?? 0 }
        }
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent("camera-upload", isDirectory: true)
        try? FileManager.default.removeItem(at: temp)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        var uploaded = 0
        var skipped: String?
        for (n, item) in items.enumerated() {
            try checkCancelled()
            if s.wifiOnly && !onWifi() { return Settings.status("waiting", "Waiting for Wi-Fi") }
            if s.chargingOnly && !isCharging() { return Settings.status("waiting", "Waiting for the charger") }
            progress("Uploading \(n + 1) of \(items.count) to \(s.folder)")
            var sent = false
            // The original, and for a Live Photo its video as a second file.
            for res in item.resources {
                let file = temp.appendingPathComponent(UUID().uuidString + "-" + res.name)
                defer { try? FileManager.default.removeItem(at: file) }
                guard let size = try export(res.resource, to: file) else {
                    skipped = "\(res.name) is larger than \(Self.maxUpload >> 30) GiB and was skipped"
                    continue
                }
                var path = item.dir + "/" + res.name
                // Already there (uploaded before the list of done items was lost).
                if existing[path] == size { continue }
                var k = 2
                while existing[path] != nil {
                    let ext = (res.name as NSString).pathExtension
                    let base = (res.name as NSString).deletingPathExtension
                    path = "\(item.dir)/\(base) (\(k))" + (ext.isEmpty ? "" : "." + ext)
                    k += 1
                }
                try api.upload(folder: s.folder, path: path, file: file) { task in
                    self.lock.lock(); self.currentTask = task; self.lock.unlock()
                }
                lock.lock(); currentTask = nil; lock.unlock()
                existing[path] = size
                sent = true
                if res.isVideo, let jpeg = VideoThumbs.frame(of: file) {
                    // The service has no ffmpeg on a phone: the frame comes from AVFoundation.
                    _ = try? api.post("/api/thumbnail", ["folder": s.folder, "path": path, "jpeg": jpeg.base64EncodedString()])
                }
                if encrypted {
                    // Folders kept encrypted on the phone need not keep the uploaded blocks
                    // once a storage has them (the service refuses otherwise); the original
                    // is still in the photo library.
                    _ = try? api.post("/api/free", ["folder": s.folder, "path": path])
                }
            }
            remember(item.key)
            if sent { uploaded += 1 }
        }
        Settings.recordUploads(uploaded)
        if let skipped = skipped { Settings.status("error", skipped) } else { Settings.status("idle", limitedNote()) }
    }

    /// With limited access iOS shows Varsto only the photos the user picked, so new ones are not seen.
    private func limitedNote() -> String? {
        PHPhotoLibrary.authorizationStatus(for: .readWrite) == .limited
            ? "Varsto can only see the photos you picked; allow access to all photos in Settings to upload new ones" : nil
    }

    /// One photo or video waiting for upload, with the files to send.
    private struct Item {
        let key: String
        let dir: String
        let resources: [Resource]
    }

    private struct Resource {
        let resource: PHAssetResource
        let name: String
        let isVideo: Bool
    }

    /// Photos and videos of the user's own library created since camera upload was switched on,
    /// oldest first, not yet uploaded; screenshots only when asked for.
    private func newItems(_ s: Settings) -> [Item] {
        let seen = loadDone()
        let opts = PHFetchOptions()
        opts.predicate = NSPredicate(format: "creationDate >= %@", Date(timeIntervalSince1970: s.since) as NSDate)
        opts.sortDescriptors = [NSSortDescriptor(key: "creationDate", ascending: true)]
        // Not iCloud Shared Albums or pictures synced from a computer.
        opts.includeAssetSourceTypes = [.typeUserLibrary]
        let assets = PHAsset.fetchAssets(with: opts)
        var out: [Item] = []
        let calendar = Calendar.current
        assets.enumerateObjects { asset, _, _ in
            guard asset.mediaType == .image || asset.mediaType == .video else { return }
            let created = asset.creationDate ?? Date(timeIntervalSince1970: s.since)
            let kind = asset.mediaType == .video ? "video" : "image"
            let key = "\(kind):\(asset.localIdentifier):\(Int64(created.timeIntervalSince1970))"
            if seen.contains(key) { return }
            if asset.mediaSubtypes.contains(.photoScreenshot) && !s.screenshots { return }
            let resources = Self.originals(of: asset, created: created)
            if resources.isEmpty { return }
            let c = calendar.dateComponents([.year, .month], from: created)
            let dir = String(format: "%04d/%02d", c.year ?? 1970, c.month ?? 1)
            out.append(Item(key: key, dir: dir, resources: resources))
        }
        return out
    }

    /// The original file of `asset` (HEIC, JPEG, RAW, MOV…, not an edited version), and the
    /// paired video of a Live Photo.
    private static func originals(of asset: PHAsset, created: Date) -> [Resource] {
        let all = PHAssetResource.assetResources(for: asset)
        let video = asset.mediaType == .video
        var out: [Resource] = []
        let main: PHAssetResource?
        if video {
            main = all.first(where: { $0.type == .video }) ?? all.first(where: { $0.type == .fullSizeVideo })
        } else {
            main = all.first(where: { $0.type == .photo }) ?? all.first(where: { $0.type == .fullSizePhoto })
        }
        if let r = main { out.append(Resource(resource: r, name: name(of: r, video: video, created: created), isVideo: video)) }
        if !video, let r = all.first(where: { $0.type == .pairedVideo }) {
            out.append(Resource(resource: r, name: name(of: r, video: true, created: created), isVideo: true))
        }
        return out
    }

    private static func name(of r: PHAssetResource, video: Bool, created: Date) -> String {
        let n = r.originalFilename.replacingOccurrences(of: "/", with: "_").trimmingCharacters(in: .whitespacesAndNewlines)
        if !n.isEmpty && n != "." && n != ".." { return n }
        return (video ? "VID_" : "IMG_") + "\(Int64(created.timeIntervalSince1970))" + (video ? ".mov" : ".jpg")
    }

    /// Write `resource` to `file` as it arrives (from iCloud if it is not on the phone).
    /// Returns its size, or nil when it is larger than the upload limit.
    private func export(_ resource: PHAssetResource, to file: URL) throws -> Int64? {
        guard FileManager.default.createFile(atPath: file.path, contents: nil) else {
            throw Failure(message: "cannot write \(file.lastPathComponent)")
        }
        let handle = try FileHandle(forWritingTo: file)
        defer { try? handle.close() }
        let options = PHAssetResourceRequestOptions()
        options.isNetworkAccessAllowed = true
        let manager = PHAssetResourceManager.default()
        let box = ExportState()
        let finished = DispatchSemaphore(value: 0)
        let id = manager.requestData(for: resource, options: options, dataReceivedHandler: { data in
            if box.stopped { return }
            box.total += Int64(data.count)
            if box.total > Self.maxUpload {
                box.stopped = true
                box.tooLarge = true
                if let id = box.id { manager.cancelDataRequest(id) }
                return
            }
            do {
                try handle.write(contentsOf: data)
            } catch {
                box.stopped = true
                box.error = error
                if let id = box.id { manager.cancelDataRequest(id) }
            }
        }, completionHandler: { error in
            if box.error == nil && !box.tooLarge { box.error = error }
            finished.signal()
        })
        box.id = id
        lock.lock(); currentRequest = id; lock.unlock()
        finished.wait()
        lock.lock(); currentRequest = nil; lock.unlock()
        try checkCancelled()
        if box.tooLarge { return nil }
        if let e = box.error { throw e }
        return box.total
    }

    /// Shared between the export's handlers, which PhotoKit calls one after another.
    private final class ExportState {
        private let lock = NSLock()
        private var _id: PHAssetResourceDataRequestID?
        var id: PHAssetResourceDataRequestID? {
            get { lock.lock(); defer { lock.unlock() }; return _id }
            set { lock.lock(); _id = newValue; lock.unlock() }
        }
        var total: Int64 = 0
        var stopped = false
        var tooLarge = false
        var error: Error?
    }

    // MARK: Done items, status, conditions

    private func loadDone() -> Set<String> {
        if let d = done { return d }
        var set = Set<String>()
        if let text = try? String(contentsOf: doneFile, encoding: .utf8) {
            for line in text.split(separator: "\n") {
                let t = line.trimmingCharacters(in: .whitespaces)
                if !t.isEmpty { set.insert(t) }
            }
        }
        done = set
        return set
    }

    private func remember(_ key: String) {
        var set = loadDone()
        set.insert(key)
        done = set
        let line = Data((key + "\n").utf8)
        if let h = try? FileHandle(forWritingTo: doneFile) {
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: line)
        } else {
            try? line.write(to: doneFile)
        }
    }

    /// On Wi-Fi (or a wired network) that is neither metered (a phone's hotspot) nor in Low Data Mode.
    private func onWifi() -> Bool {
        lock.lock(); let p = path ?? monitor.currentPath; lock.unlock()
        guard p.status == .satisfied, !p.isExpensive, !p.isConstrained else { return false }
        return p.usesInterfaceType(.wifi) || p.usesInterfaceType(.wiredEthernet)
    }

    private func isCharging() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return charging
    }

    /// "Uploading 2 of 5 to Camera" while a scan sends files (the page shows it as the status).
    private func progress(_ text: String?) {
        lock.lock(); progressText = text; lock.unlock()
        notifyChange()
    }

    fileprivate var progressMessage: String? {
        lock.lock(); defer { lock.unlock() }
        return progressText
    }

    private func notifyChange() {
        DispatchQueue.main.async { self.onChange?() }
    }

    /// What the user chose in the interface, kept in the app's preferences, with the status.
    struct Settings {
        var enabled: Bool
        var folder: String
        var wifiOnly: Bool
        var chargingOnly: Bool
        var screenshots: Bool
        /// Items created before this moment (seconds since 1970) are not "new".
        var since: Double

        private static var d: UserDefaults { UserDefaults.standard }
        private static func k(_ name: String) -> String { "camera_upload." + name }

        static func load() -> Settings {
            Settings(enabled: d.bool(forKey: k("enabled")), folder: d.string(forKey: k("folder")) ?? "",
                     wifiOnly: d.bool(forKey: k("wifi_only")), chargingOnly: d.bool(forKey: k("charging_only")),
                     screenshots: d.bool(forKey: k("screenshots")), since: d.double(forKey: k("since")))
        }

        /// Store settings from the interface; switching on starts "new" from now.
        static func save(_ json: [String: Any]) {
            let enable = json["enabled"] as? Bool ?? false
            if enable && !d.bool(forKey: k("enabled")) { d.set(Date().timeIntervalSince1970.rounded(.down), forKey: k("since")) }
            d.set(enable, forKey: k("enabled"))
            d.set((json["folder"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines), forKey: k("folder"))
            d.set(json["wifi_only"] as? Bool ?? false, forKey: k("wifi_only"))
            d.set(json["charging_only"] as? Bool ?? false, forKey: k("charging_only"))
            d.set(json["screenshots"] as? Bool ?? false, forKey: k("screenshots"))
        }

        static func status(_ state: String, _ message: String?) {
            d.set(state, forKey: k("state"))
            d.set(message ?? "", forKey: k("message"))
            d.set(Int64(Date().timeIntervalSince1970), forKey: k("checked"))
            CameraUpload.shared.notifyChange()
        }

        static func recordUploads(_ n: Int) {
            if n == 0 { return }
            d.set(d.integer(forKey: k("uploaded")) + n, forKey: k("uploaded"))
            d.set(Int64(Date().timeIntervalSince1970), forKey: k("last_upload"))
        }

        /// Settings and status for the interface, with the same fields as on Android.
        static func json() -> [String: Any] {
            let s = load()
            let progress = CameraUpload.shared.progressMessage
            return [
                "enabled": s.enabled, "folder": s.folder,
                "wifi_only": s.wifiOnly, "charging_only": s.chargingOnly,
                "screenshots": s.screenshots, "since": Int64(s.since),
                "permission": CameraUpload.hasPermission,
                "limited": PHPhotoLibrary.authorizationStatus(for: .readWrite) == .limited,
                "state": progress != nil ? "uploading" : (d.string(forKey: k("state")) ?? "idle"),
                "message": progress ?? (d.string(forKey: k("message")) ?? ""),
                "uploaded": d.integer(forKey: k("uploaded")),
                "last_upload": Int64(d.double(forKey: k("last_upload"))),
            ]
        }
    }
}

/// Minimal synchronous client of the in-process service, with the session token
/// of its start URL. Call it off the main thread.
final class LocalAPI {
    let base: String
    let token: String

    private static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 10 * 60
        c.timeoutIntervalForResource = 24 * 60 * 60
        return URLSession(configuration: c)
    }()

    init?(url: URL) {
        guard var c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let t = c.queryItems?.first(where: { $0.name == "token" })?.value, !t.isEmpty else { return nil }
        c.query = nil; c.path = ""; c.fragment = nil
        guard let b = c.string else { return nil }
        base = b
        token = t
    }

    static func connect() -> LocalAPI? {
        ServiceHost.shared.serviceURL.flatMap { LocalAPI(url: $0) }
    }

    /// Percent-encoded for a query value (also `+`, `&`, `=` and `/`).
    static func enc(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private func request(_ method: String, _ path: String) throws -> URLRequest {
        guard let url = URL(string: base + path) else { throw URLError(.badURL) }
        var req = URLRequest(url: url, timeoutInterval: 10 * 60)
        req.httpMethod = method
        req.setValue(token, forHTTPHeaderField: "X-Varsto-Token")
        return req
    }

    /// Run the task `start(handler)` makes and wait for it; the service's {"error": …} becomes the thrown message.
    private func run(_ start: (@escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionTask,
                      onTask: ((URLSessionTask) -> Void)? = nil) throws -> Data {
        var body: Data?
        var response: URLResponse?
        var failure: Error?
        let finished = DispatchSemaphore(value: 0)
        let task = start { d, r, e in
            body = d; response = r; failure = e
            finished.signal()
        }
        onTask?(task)
        task.resume()
        finished.wait()
        if let e = failure { throw e }
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        let data = body ?? Data()
        if !(200...299).contains(code) {
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            let msg = obj?["error"] as? String ?? String(data: data, encoding: .utf8) ?? ""
            throw NSError(domain: "Varsto", code: code,
                          userInfo: [NSLocalizedDescriptionKey: msg.isEmpty ? "HTTP \(code)" : msg])
        }
        return data
    }

    func get(_ path: String) throws -> Data {
        let req = try request("GET", path)
        return try run { Self.session.dataTask(with: req, completionHandler: $0) }
    }

    func object(_ path: String) throws -> [String: Any] {
        (try JSONSerialization.jsonObject(with: get(path)) as? [String: Any]) ?? [:]
    }

    func array(_ path: String) throws -> [[String: Any]] {
        (try JSONSerialization.jsonObject(with: get(path)) as? [[String: Any]]) ?? []
    }

    @discardableResult
    func post(_ path: String, _ json: [String: Any]) throws -> Data {
        var req = try request("POST", path)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: json)
        return try run { Self.session.dataTask(with: req, completionHandler: $0) }
    }

    /// `POST /api/upload?folder=…&path=…` with the file streamed as the body (with its length).
    func upload(folder: String, path: String, file: URL, onTask: ((URLSessionTask) -> Void)? = nil) throws {
        var req = try request("POST", "/api/upload?folder=" + Self.enc(folder) + "&path=" + Self.enc(path))
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        _ = try run({ Self.session.uploadTask(with: req, fromFile: file, completionHandler: $0) }, onTask: onTask)
    }
}
