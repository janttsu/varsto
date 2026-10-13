// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Native full-screen viewer for pictures, video, audio and text of a folder
// kept encrypted on the phone. Everything is read through the service's
// /api/view, which decrypts in memory (with range requests for seeking), so no
// plaintext copy is written; only Share writes a temporary decrypted file, for
// the other app, and removes it afterwards. The web page opens this through
// `window.webkit.messageHandlers.varstoViewer` (see WebBridge).
//
// UIKit rather than SwiftUI: paging, pinch-zoom and swipe-down-to-close need
// direct control over which gesture wins.
import AVFoundation
import AVKit
import ImageIO
import UIKit

/// One file of the list the page sent.
struct ViewerItem {
    let path: String
    let name: String
    /// "image", "video", "audio", "text", "pdf" or "" (the page's viewKind).
    let kind: String
    let size: Int64
    /// /api/view with the session token in the query (players cannot send a header).
    let url: URL
}

final class MediaViewerController: UIViewController, UIPageViewControllerDataSource,
    UIPageViewControllerDelegate, UIGestureRecognizerDelegate {
    private let items: [ViewerItem]
    private var index: Int
    private let pages = UIPageViewController(transitionStyle: .scroll, navigationOrientation: .horizontal,
                                             options: [.interPageSpacing: 16])
    private let bar = UIView()
    private let titleLabel = UILabel()
    private let countLabel = UILabel()
    private let doneButton = UIButton(type: .system)
    private let shareButton = UIButton(type: .system)
    private let shareSpinner = UIActivityIndicatorView(style: .medium)
    private var barsHidden = false
    private var dismissPan: UIPanGestureRecognizer!

    /// Decoded pictures: the one shown and its neighbours, downsampled to the screen.
    private let images = NSCache<NSNumber, UIImage>()
    private var loading = Set<Int>()
    private var waiting: [Int: [(UIImage?) -> Void]] = [:]
    private var maxPixel: CGFloat = 2048

    /// As in the page: asked once per app session before the first decrypted copy is shared.
    private static var shareConfirmed = false

    /// No cache on disk for anything decrypted.
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: c)
    }()

    init(items: [ViewerItem], index: Int) {
        self.items = items
        self.index = index
        super.init(nibName: nil, bundle: nil)
        images.countLimit = 5
        images.totalCostLimit = 256 << 20
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    override var prefersStatusBarHidden: Bool { barsHidden }
    override var preferredStatusBarStyle: UIStatusBarStyle { .lightContent }
    override var prefersHomeIndicatorAutoHidden: Bool { barsHidden }

    override func viewDidLoad() {
        super.viewDidLoad()
        overrideUserInterfaceStyle = .dark
        view.backgroundColor = .black
        // Video and audio play with the ringer switched off, like in Photos.
        try? AVAudioSession.sharedInstance().setCategory(.playback)

        addChild(pages)
        pages.view.frame = view.bounds
        pages.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(pages.view)
        pages.didMove(toParent: self)
        pages.dataSource = self
        pages.delegate = self
        updateMaxPixel()
        if let first = page(at: index) {
            pages.setViewControllers([first], direction: .forward, animated: false)
        }

        setUpBar()
        dismissPan = UIPanGestureRecognizer(target: self, action: #selector(dragged(_:)))
        dismissPan.delegate = self
        view.addGestureRecognizer(dismissPan)
        updateBar()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        updateMaxPixel()
    }

    /// Enough pixels to zoom in a little; much less memory than a 48-megapixel original.
    private func updateMaxPixel() {
        let scale = view.window?.screen.scale ?? max(traitCollection.displayScale, 2)
        let side = max(view.bounds.width, view.bounds.height)
        if side > 0 { maxPixel = min(4096, side * scale * 1.5) }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        preload(around: index)
    }

    // MARK: Bar

    private func setUpBar() {
        bar.backgroundColor = UIColor.black.withAlphaComponent(0.55)
        bar.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(bar)

        doneButton.setTitle(tr("Done"), for: .normal)
        doneButton.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        doneButton.tintColor = .white
        doneButton.addTarget(self, action: #selector(close), for: .touchUpInside)

        shareButton.setImage(UIImage(systemName: "square.and.arrow.up"), for: .normal)
        shareButton.tintColor = .white
        shareButton.accessibilityLabel = tr("Share")
        shareButton.addTarget(self, action: #selector(share), for: .touchUpInside)
        shareSpinner.color = .white
        shareSpinner.hidesWhenStopped = true

        titleLabel.textColor = .white
        titleLabel.font = .preferredFont(forTextStyle: .subheadline)
        titleLabel.textAlignment = .center
        titleLabel.lineBreakMode = .byTruncatingMiddle
        countLabel.textColor = UIColor.white.withAlphaComponent(0.7)
        countLabel.font = .preferredFont(forTextStyle: .caption1)
        countLabel.textAlignment = .center
        let titles = UIStackView(arrangedSubviews: [titleLabel, countLabel])
        titles.axis = .vertical
        titles.alignment = .fill

        for v in [doneButton, shareButton, shareSpinner, titles] as [UIView] {
            v.translatesAutoresizingMaskIntoConstraints = false
            bar.addSubview(v)
        }
        let guide = view.safeAreaLayoutGuide
        NSLayoutConstraint.activate([
            bar.topAnchor.constraint(equalTo: view.topAnchor),
            bar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            bar.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            bar.bottomAnchor.constraint(equalTo: guide.topAnchor, constant: 52),

            doneButton.leadingAnchor.constraint(equalTo: guide.leadingAnchor, constant: 16),
            doneButton.bottomAnchor.constraint(equalTo: bar.bottomAnchor, constant: -8),
            shareButton.trailingAnchor.constraint(equalTo: guide.trailingAnchor, constant: -16),
            shareButton.centerYAnchor.constraint(equalTo: doneButton.centerYAnchor),
            shareButton.widthAnchor.constraint(equalToConstant: 44),
            shareButton.heightAnchor.constraint(equalToConstant: 44),
            shareSpinner.centerXAnchor.constraint(equalTo: shareButton.centerXAnchor),
            shareSpinner.centerYAnchor.constraint(equalTo: shareButton.centerYAnchor),

            titles.centerXAnchor.constraint(equalTo: bar.centerXAnchor),
            titles.centerYAnchor.constraint(equalTo: doneButton.centerYAnchor),
            titles.leadingAnchor.constraint(greaterThanOrEqualTo: doneButton.trailingAnchor, constant: 12),
            titles.trailingAnchor.constraint(lessThanOrEqualTo: shareButton.leadingAnchor, constant: -12),
        ])
    }

    private func updateBar() {
        let item = items[index]
        titleLabel.text = item.name
        countLabel.text = items.count > 1 ? "\(index + 1) / \(items.count)" : nil
        countLabel.isHidden = items.count <= 1
    }

    /// A tap on a picture shows or hides the bar.
    func toggleBars() {
        barsHidden.toggle()
        UIView.animate(withDuration: 0.2) {
            self.bar.alpha = self.barsHidden ? 0 : 1
            self.setNeedsStatusBarAppearanceUpdate()
        }
        setNeedsUpdateOfHomeIndicatorAutoHidden()
    }

    @objc private func close() {
        dismiss(animated: true)
    }

    // MARK: Pages

    private func page(at i: Int) -> ViewerPage? {
        guard items.indices.contains(i) else { return nil }
        let item = items[i]
        let p: ViewerPage
        switch item.kind {
        case "image": p = ImagePage(index: i, item: item)
        case "video", "audio": p = PlayerPage(index: i, item: item)
        case "text": p = TextPage(index: i, item: item)
        default: p = MessagePage(index: i, item: item, text: tr("This kind of file cannot be shown here. Share hands a decrypted copy to another app."))
        }
        p.viewer = self
        return p
    }

    func pageViewController(_ pageViewController: UIPageViewController,
                            viewControllerBefore viewController: UIViewController) -> UIViewController? {
        guard let p = viewController as? ViewerPage else { return nil }
        return page(at: p.index - 1)
    }

    func pageViewController(_ pageViewController: UIPageViewController,
                            viewControllerAfter viewController: UIViewController) -> UIViewController? {
        guard let p = viewController as? ViewerPage else { return nil }
        return page(at: p.index + 1)
    }

    func pageViewController(_ pageViewController: UIPageViewController, didFinishAnimating finished: Bool,
                            previousViewControllers: [UIViewController], transitionCompleted completed: Bool) {
        guard completed, let p = pages.viewControllers?.first as? ViewerPage else { return }
        index = p.index
        updateBar()
        preload(around: index)
    }

    private var currentPage: ViewerPage? { pages.viewControllers?.first as? ViewerPage }

    // MARK: Pictures

    /// Decode the picture of item `i` (cached), downsampled to about the screen size.
    /// `done` runs on the main thread with nil when it cannot be shown.
    func image(at i: Int, _ done: ((UIImage?) -> Void)?) {
        let key = NSNumber(value: i)
        if let img = images.object(forKey: key) { done?(img); return }
        if let done = done { waiting[i, default: []].append(done) }
        if loading.contains(i) || !items.indices.contains(i) { return }
        loading.insert(i)
        let maxPixel = self.maxPixel
        var req = URLRequest(url: items[i].url, timeoutInterval: 120)
        req.cachePolicy = .reloadIgnoringLocalCacheData
        Self.session.dataTask(with: req) { [weak self] data, resp, _ in
            var image: UIImage?
            if let data = data, (resp as? HTTPURLResponse)?.statusCode == 200 {
                image = Self.downsample(data, maxPixel: maxPixel)
            }
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.loading.remove(i)
                if let img = image {
                    let cost = Int(img.size.width * img.size.height * img.scale * img.scale * 4)
                    self.images.setObject(img, forKey: key, cost: cost)
                }
                let callbacks = self.waiting.removeValue(forKey: i) ?? []
                callbacks.forEach { $0(image) }
            }
        }.resume()
    }

    /// Decode with ImageIO straight to the wanted size (HEIC, JPEG, PNG… with the EXIF orientation applied).
    static func downsample(_ data: Data, maxPixel: CGFloat) -> UIImage? {
        let sourceOptions = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let source = CGImageSourceCreateWithData(data as CFData, sourceOptions) else { return nil }
        let options = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                       kCGImageSourceShouldCacheImmediately: true,
                       kCGImageSourceCreateThumbnailWithTransform: true,
                       kCGImageSourceThumbnailMaxPixelSize: maxPixel] as CFDictionary
        guard let cg = CGImageSourceCreateThumbnailAtIndex(source, 0, options) else { return nil }
        return UIImage(cgImage: cg)
    }

    private func preload(around i: Int) {
        for j in [i + 1, i - 1] where items.indices.contains(j) && items[j].kind == "image" {
            image(at: j, nil)
        }
    }

    // MARK: Swipe down to close

    func gestureRecognizerShouldBegin(_ g: UIGestureRecognizer) -> Bool {
        guard g === dismissPan else { return true }
        if currentPage?.blocksDismiss == true { return false }
        let v = dismissPan.velocity(in: view)
        return v.y > 0 && v.y > abs(v.x) * 1.5
    }

    func gestureRecognizer(_ g: UIGestureRecognizer,
                           shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool {
        // The picture's scroll view and the pager do not move vertically at normal size.
        g === dismissPan
    }

    @objc private func dragged(_ g: UIPanGestureRecognizer) {
        let t = g.translation(in: view)
        switch g.state {
        case .changed:
            let y = max(0, t.y)
            pages.view.transform = CGAffineTransform(translationX: 0, y: y)
            view.backgroundColor = UIColor.black.withAlphaComponent(1 - min(0.8, y / 500))
            bar.alpha = barsHidden ? 0 : max(0, 1 - y / 150)
        case .ended, .cancelled, .failed:
            let v = g.velocity(in: view).y
            if g.state == .ended && (t.y > 120 || v > 1000) {
                close()
            } else {
                UIView.animate(withDuration: 0.25) {
                    self.pages.view.transform = .identity
                    self.view.backgroundColor = .black
                    self.bar.alpha = self.barsHidden ? 0 : 1
                }
            }
        default:
            break
        }
    }

    // MARK: Share

    @objc private func share() {
        let item = items[index]
        let go: () -> Void = { [weak self] in self?.shareCopy(of: item) }
        if Self.shareConfirmed { go(); return }
        let a = UIAlertController(
            title: tr("Share a decrypted copy?"),
            message: tr("Varsto makes a decrypted copy of {} for the app you choose and removes its own copy afterwards; the other app may keep its own.", item.name),
            preferredStyle: .alert)
        a.addAction(UIAlertAction(title: tr("Cancel"), style: .cancel))
        a.addAction(UIAlertAction(title: tr("Share"), style: .default) { _ in
            Self.shareConfirmed = true
            go()
        })
        present(a, animated: true)
    }

    /// Fetch the whole file through /api/view into a private temporary directory, hand it to the
    /// share sheet, and remove it once the sheet is closed.
    private func shareCopy(of item: ViewerItem) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("share-" + UUID().uuidString, isDirectory: true)
        let name = item.name.replacingOccurrences(of: "/", with: "_")
        let file = dir.appendingPathComponent(name.isEmpty ? "file" : name)
        shareButton.isHidden = true
        shareSpinner.startAnimating()
        Self.download(item.url, to: file, dir: dir) { [weak self] error in
            guard let self = self else { try? FileManager.default.removeItem(at: dir); return }
            self.shareSpinner.stopAnimating()
            self.shareButton.isHidden = false
            if let error = error {
                try? FileManager.default.removeItem(at: dir)
                let a = UIAlertController(title: nil, message: tr("Could not share the file: {}", error.localizedDescription), preferredStyle: .alert)
                a.addAction(UIAlertAction(title: "OK", style: .default))
                self.present(a, animated: true)
                return
            }
            let sheet = UIActivityViewController(activityItems: [file], applicationActivities: nil)
            sheet.completionWithItemsHandler = { _, _, _, _ in
                try? FileManager.default.removeItem(at: dir)
            }
            // iPad: the sheet is a popover from the button.
            sheet.popoverPresentationController?.sourceView = self.shareButton
            sheet.popoverPresentationController?.sourceRect = self.shareButton.bounds
            self.present(sheet, animated: true)
        }
    }

    /// Download `url` to `file` in ranges (the service answers at most 8 MiB per request and
    /// refuses a whole file over 256 MiB). `done` runs on the main thread.
    static func download(_ url: URL, to file: URL, dir: URL, done: @escaping (Error?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            var failure: Error?
            do {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                guard FileManager.default.createFile(atPath: file.path, contents: nil) else { throw URLError(.cannotCreateFile) }
                let handle = try FileHandle(forWritingTo: file)
                defer { try? handle.close() }
                let window: Int64 = 8 << 20
                var start: Int64 = 0
                var total: Int64 = -1
                while total < 0 || start < total {
                    var req = URLRequest(url: url, timeoutInterval: 120)
                    req.setValue("bytes=\(start)-\(start + window - 1)", forHTTPHeaderField: "Range")
                    let (data, resp) = try fetch(req)
                    if resp.statusCode == 200 {
                        // The whole file in one answer.
                        try handle.write(contentsOf: data)
                        break
                    }
                    if resp.statusCode == 416 && start == 0 { break } // an empty file
                    guard resp.statusCode == 206 else {
                        let msg = String(data: data, encoding: .utf8) ?? ""
                        throw NSError(domain: "Varsto", code: resp.statusCode,
                                      userInfo: [NSLocalizedDescriptionKey: msg.isEmpty ? "HTTP \(resp.statusCode)" : msg])
                    }
                    guard !data.isEmpty, let range = resp.value(forHTTPHeaderField: "Content-Range"),
                          let slash = range.lastIndex(of: "/"),
                          let size = Int64(range[range.index(after: slash)...]) else { throw URLError(.badServerResponse) }
                    total = size
                    try handle.write(contentsOf: data)
                    start += Int64(data.count)
                }
            } catch {
                failure = error
            }
            DispatchQueue.main.async { done(failure) }
        }
    }

    private static func fetch(_ req: URLRequest) throws -> (Data, HTTPURLResponse) {
        var out: (Data?, URLResponse?, Error?) = (nil, nil, nil)
        let finished = DispatchSemaphore(value: 0)
        session.dataTask(with: req) { d, r, e in
            out = (d, r, e)
            finished.signal()
        }.resume()
        finished.wait()
        if let e = out.2 { throw e }
        guard let resp = out.1 as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (out.0 ?? Data(), resp)
    }
}

/// One page of the viewer: the file at `index` of the list.
class ViewerPage: UIViewController {
    let index: Int
    let item: ViewerItem
    weak var viewer: MediaViewerController?
    /// True while swiping down should move the content instead (a zoomed picture).
    var blocksDismiss: Bool { false }

    init(index: Int, item: ViewerItem) {
        self.index = index
        self.item = item
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .clear
    }

    /// A line of text in the middle of the page.
    func showMessage(_ text: String) {
        let label = UILabel()
        label.text = text
        label.textColor = UIColor.white.withAlphaComponent(0.8)
        label.numberOfLines = 0
        label.textAlignment = .center
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            label.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor, constant: 16),
            label.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor, constant: -16),
        ])
    }
}

/// A picture that zooms with a pinch or a double tap.
final class ImagePage: ViewerPage, UIScrollViewDelegate {
    private let scroll = UIScrollView()
    private let imageView = UIImageView()
    private let spinner = UIActivityIndicatorView(style: .large)
    private var laidOutFor: CGSize = .zero

    override var blocksDismiss: Bool { scroll.zoomScale > scroll.minimumZoomScale + 0.01 }

    override func viewDidLoad() {
        super.viewDidLoad()
        scroll.frame = view.bounds
        scroll.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        scroll.delegate = self
        scroll.minimumZoomScale = 1
        scroll.maximumZoomScale = 4
        scroll.showsVerticalScrollIndicator = false
        scroll.showsHorizontalScrollIndicator = false
        scroll.contentInsetAdjustmentBehavior = .never
        scroll.decelerationRate = .fast
        view.addSubview(scroll)
        imageView.contentMode = .scaleAspectFit
        scroll.addSubview(imageView)

        spinner.color = .white
        spinner.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(spinner)
        NSLayoutConstraint.activate([
            spinner.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
        spinner.startAnimating()

        let double = UITapGestureRecognizer(target: self, action: #selector(doubleTapped(_:)))
        double.numberOfTapsRequired = 2
        scroll.addGestureRecognizer(double)
        let single = UITapGestureRecognizer(target: self, action: #selector(tapped))
        single.require(toFail: double)
        scroll.addGestureRecognizer(single)

        viewer?.image(at: index) { [weak self] img in
            guard let self = self else { return }
            self.spinner.stopAnimating()
            if let img = img {
                self.imageView.image = img
                self.laidOutFor = .zero
                self.view.setNeedsLayout()
            } else {
                self.showMessage(tr("This file cannot be shown here."))
            }
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if scroll.bounds.size != laidOutFor { layoutImage() }
    }

    /// Fit the picture to the page at normal size, centred.
    private func layoutImage() {
        guard let img = imageView.image, img.size.width > 0, img.size.height > 0,
              scroll.bounds.width > 0, scroll.bounds.height > 0 else { return }
        laidOutFor = scroll.bounds.size
        scroll.zoomScale = 1
        let b = scroll.bounds.size
        let fit = min(b.width / img.size.width, b.height / img.size.height)
        let size = CGSize(width: img.size.width * fit, height: img.size.height * fit)
        imageView.frame = CGRect(origin: .zero, size: size)
        scroll.contentSize = size
        center()
    }

    private func center() {
        let b = scroll.bounds.size
        let c = scroll.contentSize
        let dx = max(0, (b.width - c.width) / 2)
        let dy = max(0, (b.height - c.height) / 2)
        scroll.contentInset = UIEdgeInsets(top: dy, left: dx, bottom: dy, right: dx)
    }

    func viewForZooming(in scrollView: UIScrollView) -> UIView? { imageView }

    func scrollViewDidZoom(_ scrollView: UIScrollView) { center() }

    @objc private func doubleTapped(_ g: UITapGestureRecognizer) {
        if scroll.zoomScale > scroll.minimumZoomScale + 0.01 {
            scroll.setZoomScale(scroll.minimumZoomScale, animated: true)
            return
        }
        let p = g.location(in: imageView)
        let s: CGFloat = 2.5
        let w = scroll.bounds.width / s
        let h = scroll.bounds.height / s
        scroll.zoom(to: CGRect(x: p.x - w / 2, y: p.y - h / 2, width: w, height: h), animated: true)
    }

    @objc private func tapped() { viewer?.toggleBars() }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // Back at normal size when it is swiped back to.
        if scroll.zoomScale != scroll.minimumZoomScale { scroll.setZoomScale(scroll.minimumZoomScale, animated: false) }
    }
}

/// Video or audio, played by AVKit from /api/view with range requests for seeking.
/// The player exists only while the page is on screen.
final class PlayerPage: ViewerPage {
    private let playerController = AVPlayerViewController()

    override func viewDidLoad() {
        super.viewDidLoad()
        addChild(playerController)
        playerController.view.frame = view.bounds
        playerController.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        playerController.view.backgroundColor = .clear
        playerController.videoGravity = .resizeAspect
        // Its own controls below the viewer's bar.
        playerController.additionalSafeAreaInsets = UIEdgeInsets(top: 52, left: 0, bottom: 0, right: 0)
        view.addSubview(playerController.view)
        playerController.didMove(toParent: self)
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if playerController.player == nil {
            playerController.player = AVPlayer(playerItem: AVPlayerItem(asset: AVURLAsset(url: item.url)))
        }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        playerController.player?.pause()
        playerController.player = nil
    }
}

/// The start of a text file (256 KiB, as in the page).
final class TextPage: ViewerPage {
    private let textView = UITextView()

    override func viewDidLoad() {
        super.viewDidLoad()
        textView.isEditable = false
        textView.backgroundColor = .clear
        textView.textColor = .white
        textView.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        textView.textContainerInset = UIEdgeInsets(top: 16, left: 12, bottom: 24, right: 12)
        textView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 52),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            textView.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
        ])
        var req = URLRequest(url: item.url, timeoutInterval: 60)
        req.setValue("bytes=0-262143", forHTTPHeaderField: "Range")
        let more = item.size > 262_144
        MediaViewerController.session.dataTask(with: req) { [weak self] data, resp, _ in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            let text = data.flatMap { (code == 200 || code == 206) ? String(decoding: $0, as: UTF8.self) : nil }
            DispatchQueue.main.async {
                guard let self = self else { return }
                if let t = text {
                    self.textView.text = t + (more ? "\n…" : "")
                } else {
                    self.showMessage(tr("This file cannot be shown here."))
                }
            }
        }.resume()
    }
}

/// Files the viewer cannot show (PDF and others): a line of text and the Share button above.
final class MessagePage: ViewerPage {
    private let text: String

    init(index: Int, item: ViewerItem, text: String) {
        self.text = text
        super.init(index: index, item: item)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    override func viewDidLoad() {
        super.viewDidLoad()
        showMessage(text)
    }
}
