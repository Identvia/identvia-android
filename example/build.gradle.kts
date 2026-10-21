plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.identvianotes"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.example.identvianotes"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
        // Register com.example.identvianotes:/oauth/identvia on a *public* Identvia client.
        manifestPlaceholders["identviaRedirectScheme"] = "com.example.identvianotes"
        buildConfigField("String", "IDENTVIA_CLIENT_ID", "\"${project.findProperty("identviaClientId") ?: "oid_your_client_id"}\"")
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":identvia-android"))
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.activity:activity-ktx:1.9.2")
}
