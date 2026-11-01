import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Release signing is read from an untracked keystore.properties at the repo root
// (keys: storeFile, storePassword, keyAlias, keyPassword), so no signing secret
// is ever committed. When the file is absent — CI, a fresh clone, a debug-only
// workflow — `assembleRelease` still builds; it is simply left unsigned.
//
// "../" because the Gradle root is android/, not the repo: settings.gradle.kts
// lives beside this module's parent, so rootProject.file("keystore.properties")
// resolves to android/keystore.properties. That is NOT where the release
// scripts, the .gitignore entry or any of this documentation put the file, and
// the only symptom of the mismatch is a release build that quietly comes out
// unsigned — `./gradlew :app:signingReport` showing "Config: none" with the
// file sitting right there — so the path is spelled out rather than inferred.
val keystorePropsFile = rootProject.file("../keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

android {
    namespace = "org.molepipe.molepipe"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.molepipe.app"
        minSdk = 24
        targetSdk = 37
        // Version identity is release-driven: the release build passes
        // -PonionVersionCode / -PonionVersionName (from tools/build-release.sh,
        // which derives them from the git tag). A plain debug build takes the
        // fallbacks below, so `./gradlew assembleDebug` still works with no args.
        // versionCode MUST increase every release — Android decides "is this
        // build newer" by versionCode alone, so it is what the update path keys on.
        versionCode = (project.findProperty("onionVersionCode") as String?)?.toIntOrNull() ?: 1
        versionName = (project.findProperty("onionVersionName") as String?) ?: "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // The ABIs the backend exists for. build-aar.sh cross-compiles torhost
        // and gomobile-binds the Go backend for exactly these two, so
        // libgojni.so only ever exists for arm64-v8a and x86_64.
        //
        // This has to be declared, not left implicit, because other
        // dependencies (androidx.graphics.path) ship all four ABIs. Without the
        // filter the app bundle gains armeabi-v7a and x86 lib directories
        // carrying those libraries and NOT libgojni.so — and Play reads a
        // bundle's lib directories as the list of devices the app supports. It
        // would then offer the app to 32-bit-only phones, hand them a split
        // with no backend in it, and the first launch would die in
        // System.loadLibrary. Restricting it here means Play excludes those
        // devices from the listing instead, which is the honest answer: there
        // is no 32-bit build to give them.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (keystorePropsFile.exists()) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }
    buildTypes {
        release {
            // R8 enabled with keep rules for gomobile bindings. The gomobile
            // bridge uses concrete classes (not reflection), so we keep only
            // the specific packages that gomobile and JNI generate.
            optimization {
                enable = true
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            isDebuggable = false // explicit; also gates BuildConfig.DEBUG (WebView debugging)
            if (keystorePropsFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true // MainActivity gates WebView debugging on BuildConfig.DEBUG
    }
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    // The Go backend, bound with gomobile into app/libs/mobile.aar by
    // android/build-aar.sh. This is a build artifact (per-ABI native code), so
    // it is git-ignored and must be generated before the app will compile.
    implementation(files("libs/mobile.aar"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}