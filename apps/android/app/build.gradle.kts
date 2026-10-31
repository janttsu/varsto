import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// versionName is the workspace version. versionCode for 0.0.1-alpha.N is N,
// and only when N > 13: 0.0.1-alpha.13 already shipped as versionCode 13.
// Any other shape fails configuration instead of keeping 13.
fun workspaceVersion(): String {
    val cargo = rootProject.projectDir.resolve("../../Cargo.toml")
    if (!cargo.isFile) error("Cargo.toml not found at ${cargo.absolutePath}")
    val text = cargo.readText()
    val section = Regex("""(?ms)^\[workspace\.package\]\s*(.*?)(?=^\[|\z)""").find(text)
        ?: error("no [workspace.package] in ${cargo.absolutePath}")
    val version = Regex("""(?m)^version\s*=\s*"([^"]+)"""").find(section.groupValues[1])
        ?: error("no version in [workspace.package] of ${cargo.absolutePath}")
    return version.groupValues[1]
}

fun androidVersionCode(version: String): Int {
    val match = Regex("""^0\.0\.1-alpha\.(\d+)$""").matchEntire(version)
        ?: error("Android versionCode: cannot map '$version' (expected 0.0.1-alpha.N with N > 13). Refusing to keep versionCode 13.")
    val n = match.groupValues[1].toInt()
    if (n <= 13) {
        error("Android versionCode: $version maps to $n, which does not upgrade the already-shipped code 13.")
    }
    return n
}

val varstoVersion = workspaceVersion()
val varstoVersionCode = androidVersionCode(varstoVersion)

fun envOrBlank(name: String): String? = System.getenv(name)?.takeIf { it.isNotBlank() }

val releaseKeystore = envOrBlank("VARSTO_ANDROID_KEYSTORE")
val releaseStorePassword = envOrBlank("VARSTO_ANDROID_KEYSTORE_PASSWORD")
val releaseKeyAlias = envOrBlank("VARSTO_ANDROID_KEY_ALIAS")
val releaseKeyPassword = envOrBlank("VARSTO_ANDROID_KEY_PASSWORD")

fun requireReleaseSigning() {
    val missing = listOf(
        "VARSTO_ANDROID_KEYSTORE",
        "VARSTO_ANDROID_KEYSTORE_PASSWORD",
        "VARSTO_ANDROID_KEY_ALIAS",
        "VARSTO_ANDROID_KEY_PASSWORD",
    ).filter { envOrBlank(it) == null }
    if (missing.isNotEmpty()) {
        error("assembleRelease requires ${missing.joinToString(", ")}. Refusing to sign a release APK with the debug keystore.")
    }
    val store = File(envOrBlank("VARSTO_ANDROID_KEYSTORE")!!)
    if (!store.isFile) {
        error("VARSTO_ANDROID_KEYSTORE is not a file (${store.path}). Refusing an unsigned or debug-signed release APK.")
    }
}

fun taskRequestsRelease(name: String): Boolean {
    val leaf = name.substringAfterLast(':')
    return leaf == "assemble" || leaf == "build" ||
        leaf == "assembleRelease" || leaf == "packageRelease" || leaf == "bundleRelease" ||
        leaf.startsWith("signRelease") ||
        (leaf.endsWith("Release") && (leaf.startsWith("assemble") || leaf.startsWith("bundle") || leaf.startsWith("install")))
}

android {
    namespace = "in.soderlund.varsto"
    compileSdk = 35
    defaultConfig {
        applicationId = "in.soderlund.varsto"
        minSdk = 26
        targetSdk = 35
        versionCode = varstoVersionCode
        versionName = varstoVersion
    }
    signingConfigs {
        if (releaseKeystore != null && releaseStorePassword != null && releaseKeyAlias != null && releaseKeyPassword != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            isDebuggable = false
            // Unsigned unless the four VARSTO_ANDROID_* variables name a real store.
            // Never signingConfigs.debug: a per-run debug key cannot update the last install.
            if (releaseKeystore != null && releaseStorePassword != null && releaseKeyAlias != null && releaseKeyPassword != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    // The Rust binary is shipped as lib<name>.so so that Android extracts it to
    // nativeLibraryDir, where it can be executed.
    packaging { jniLibs { useLegacyPackaging = true } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}

logger.lifecycle("Varsto Android versionName=$varstoVersion versionCode=$varstoVersionCode")

val appProject = project
gradle.taskGraph.whenReady {
    val release = allTasks.any { it.project == appProject && taskRequestsRelease(it.name) }
    if (release) requireReleaseSigning()
}
if (gradle.startParameter.taskNames.any(::taskRequestsRelease)) {
    requireReleaseSigning()
}
