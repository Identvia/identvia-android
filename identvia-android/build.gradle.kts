plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("com.vanniktech.maven.publish")
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
    lint { abortOnError = true; warningsAsErrors = false }
}

dependencies {
    api(project(":identvia-core"))
    implementation("androidx.browser:browser:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}


// Shared POM metadata for Maven Central. Credentials and the signing key come from env vars in CI only:
// ORG_GRADLE_PROJECT_mavenCentralUsername / _mavenCentralPassword (Central Portal user token),
// ORG_GRADLE_PROJECT_signingInMemoryKey / _signingInMemoryKeyId / _signingInMemoryKeyPassword (GPG).
mavenPublishing {
    publishToMavenCentral()
    // Sign whenever a key is configured (CI); local `publishToMavenLocal` works without one.
    if (!providers.gradleProperty("signingInMemoryKey").orNull.isNullOrBlank()) signAllPublications()
    coordinates("com.identvia", "identvia-android", version.toString())
    pom {
        name.set("Identvia for Android")
        description.set("Sign in with Identvia for Android: OpenID Connect + PKCE in Chrome Custom Tabs, Android Keystore token storage and Kotlin coroutines.")
        inceptionYear.set("2026")
        url.set("https://identvia.com")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("identvia")
                name.set("Identvia")
                email.set("hello@identvia.com")
                url.set("https://identvia.com")
            }
        }
        scm {
            url.set("https://github.com/Identvia/identvia-android")
            connection.set("scm:git:https://github.com/Identvia/identvia-android.git")
            developerConnection.set("scm:git:ssh://git@github.com/Identvia/identvia-android.git")
        }
        issueManagement {
            system.set("GitHub")
            url.set("https://github.com/Identvia/identvia-android/issues")
        }
    }
}

mavenPublishing {
    configure(com.vanniktech.maven.publish.AndroidSingleVariantLibrary(variant = "release", sourcesJar = true, publishJavadocJar = true))
}
