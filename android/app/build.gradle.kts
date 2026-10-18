import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing from the environment (CI) or android/keystore.properties
// (local); without either, release builds are left unsigned.
val signing = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
    System.getenv("ENCLAVEDNS_KEYSTORE")?.let { setProperty("storeFile", it) }
    System.getenv("ENCLAVEDNS_KEYSTORE_PASSWORD")?.let { setProperty("storePassword", it); setProperty("keyPassword", it) }
    System.getenv("ENCLAVEDNS_KEY_ALIAS")?.let { setProperty("keyAlias", it) }
}

android {
    namespace = "host.enclave.dns"
    compileSdk = 35
    ndkVersion = "28.1.13356709"

    defaultConfig {
        applicationId = "host.enclave.dns"
        minSdk = 26
        targetSdk = 35
        versionCode = (System.getenv("ENCLAVEDNS_VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("ENCLAVEDNS_VERSION") ?: "0.1.0"
    }

    signingConfigs {
        if (signing.getProperty("storeFile") != null) {
            create("release") {
                storeFile = file(signing.getProperty("storeFile"))
                storePassword = signing.getProperty("storePassword")
                keyAlias = signing.getProperty("keyAlias")
                keyPassword = signing.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    packaging { jniLibs { useLegacyPackaging = false } }
}

// The Rust engine (android/rust) for both ABIs, before every build.
val cargoNdk by tasks.registering(Exec::class) {
    workingDir = rootProject.projectDir.parentFile
    commandLine(
        "cargo", "ndk", "-t", "arm64-v8a", "-t", "x86_64", "-P", "26",
        "-o", file("src/main/jniLibs").absolutePath,
        "build", "--release", "-p", "enclavedns-android",
    )
}
tasks.named("preBuild") { dependsOn(cargoNdk) }
