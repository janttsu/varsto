plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "in.soderlund.varsto"
    compileSdk = 35
    defaultConfig {
        applicationId = "in.soderlund.varsto"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.0.1-alpha.2"
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    // The Rust binary is shipped as lib<name>.so so that Android extracts it to
    // nativeLibraryDir, where it can be executed.
    packaging { jniLibs { useLegacyPackaging = true } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.webkit:webkit:1.12.1")
}
