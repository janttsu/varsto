// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Background work: iOS lets an app run only when it decides to, through
// BGTaskScheduler. Two tasks share one handler: a short app refresh (about 30
// seconds, for a sync and a few uploads) and a longer processing task for camera
// upload, which iOS tends to run at night while the phone charges.
import BackgroundTasks
import Foundation

enum Background {
    /// Both identifiers are listed under BGTaskSchedulerPermittedIdentifiers in project.yml.
    static let refreshID = "in.soderlund.varsto.ios.refresh"
    static let processingID = "in.soderlund.varsto.ios.camera-upload"

    /// Register the handlers; must happen before the app finishes launching.
    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: refreshID, using: nil) { task in
            run(task, sync: true)
        }
        BGTaskScheduler.shared.register(forTaskWithIdentifier: processingID, using: nil) { task in
            run(task, sync: false)
        }
    }

    /// Ask iOS for the next runs (it decides when, if at all). Called when the app goes to the
    /// background, when the camera upload settings change and from each task.
    static func schedule() {
        let refresh = BGAppRefreshTaskRequest(identifier: refreshID)
        refresh.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(refresh)
        let s = CameraUpload.Settings.load()
        guard s.enabled, !s.folder.isEmpty else {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: processingID)
            return
        }
        let processing = BGProcessingTaskRequest(identifier: processingID)
        processing.requiresNetworkConnectivity = true
        processing.requiresExternalPower = s.chargingOnly
        processing.earliestBeginDate = Date(timeIntervalSinceNow: 5 * 60)
        try? BGTaskScheduler.shared.submit(processing)
    }

    /// Wait for the service, upload new photos and videos, then (app refresh) sync once.
    /// The task is completed exactly once: when the work ends or when iOS ends it.
    private static func run(_ task: BGTask, sync: Bool) {
        schedule()
        let once = Once()
        let finish: (Bool) -> Void = { ok in
            if once.first() { task.setTaskCompleted(success: ok) }
        }
        task.expirationHandler = {
            CameraUpload.shared.cancelRunning()
            finish(false)
        }
        // The service was started at launch (AppDelegate); it needs a moment to listen.
        ServiceHost.shared.whenReady(timeout: 15) { url in
            guard url != nil else { finish(false); return }
            CameraUpload.shared.runNow {
                if sync && !once.isDone, let api = LocalAPI.connect() {
                    _ = try? api.post("/api/sync", [:])
                }
                finish(true)
            }
        }
    }

    /// A flag that is set once, from any thread.
    private final class Once {
        private let lock = NSLock()
        private var done = false
        var isDone: Bool { lock.lock(); defer { lock.unlock() }; return done }
        /// True only for the first caller.
        func first() -> Bool {
            lock.lock(); defer { lock.unlock() }
            if done { return false }
            done = true
            return true
        }
    }
}
