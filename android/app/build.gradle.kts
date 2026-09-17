import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Release signing is read from an untracked keystore.properties at the repo root
// (keys: storeFile, storePassword, keyAlias, keyPassword), so no signing secret
// is ever committed. When the file is absent — CI, a fresh clone, a debug-only
// workflow — `assembleRelease` still builds; it is simply left unsigned.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

android {
    namespace = "org.molepipe.molepipe"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.molepipe.molepipe"
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