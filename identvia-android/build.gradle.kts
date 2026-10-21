plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

android {
    namespace = "com.identvia.android"
    compileSdk = 34
    defaultConfig {
        minSdk = 23 // AndroidKeyStore AES-GCM
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    publishing { singleVariant("release") { withSourcesJar() } }
    lint { abortOnError = true; warningsAsErrors = false }
}

dependencies {
    api(project(":identvia-core"))
    implementation("androidx.browser:browser:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}

publishing {
    publications {
        create<MavenPublication>("release") {
            artifactId = "identvia-android"
            afterEvaluate { from(components["release"]) }
        }
    }
}
