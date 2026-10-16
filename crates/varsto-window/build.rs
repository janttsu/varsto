// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Put the brand icon and the version into varsto-window.exe (Windows targets
// only; the resource compiler is windres from mingw-w64 when cross-compiling).
fn main() {
    println!("cargo:rerun-if-changed=../../brand/varsto.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    // Resource 1 is the icon the window loads for its title bar and taskbar button.
    res.set_icon("../../brand/varsto.ico");
    res.set("FileDescription", "Varsto");
    res.set("ProductName", "Varsto");
    res.set("CompanyName", "Varsto");
    res.set("LegalCopyright", "Varsto");
    if let Err(e) = res.compile() {
        // A build without the icon is still a working app.
        println!("cargo:warning=could not embed the icon: {e}");
    }
}
