plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "org.pactmesh.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.pactmesh.android"
        // 26 is what the native library is built against (`cargo ndk --platform 26`).
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.5.0-beta.8"
        // arm64 only. Every extra ABI is another full LTO link of the whole core,
        // and there is no 32-bit phone worth the build time.
        ndk { abiFilters += "arm64-v8a" }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    // `build-native.sh` drops libpactmesh_android.so here; Gradle only packages it.
    // No externalNativeBuild: cargo, not CMake, owns the Rust build.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        // The .so is already stripped and must stay page-aligned for API 23+ to
        // load it straight out of the APK.
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.zxing.embedded)
}
