plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.privet.privet_app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.privet.privet_app"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

// Ensure the native library exists for the correct ABI.
tasks.whenTaskAdded {
    if (name.startsWith("merge") && name.endsWith("NativeLibs")) {
        doFirst {
            val jniDir = file("src/main/jniLibs/arm64-v8a")
            val soFile = File(jniDir, "libprivet_ffi.so")
            if (!soFile.exists()) {
                throw GradleException(
                    "libprivet_ffi.so not found at $soFile\n" +
                    "Run the build script first:\n" +
                    "  bash scripts/build-android-rust.sh"
                )
            }
            println("Found native library: ${soFile.absolutePath}")
        }
    }
}
