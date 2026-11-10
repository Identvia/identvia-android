plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.serialization")
    `java-library`
    id("com.vanniktech.maven.publish")
}

// Bytecode 17 so Android (D8) and any JVM 17+ can consume it; builds with any JDK 17+.
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    // The local dev server may listen on [::1] only.
    systemProperty("java.net.preferIPv6Addresses", "true")
    environment("IDENTVIA_LIVE_STATE", System.getenv("IDENTVIA_LIVE_STATE") ?: "")
    testLogging { events("failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}


// Shared POM metadata for Maven Central. Credentials and the signing key come from env vars in CI only:
// ORG_GRADLE_PROJECT_mavenCentralUsername / _mavenCentralPassword (Central Portal user token),
// ORG_GRADLE_PROJECT_signingInMemoryKey / _signingInMemoryKeyId / _signingInMemoryKeyPassword (GPG).
mavenPublishing {
    publishToMavenCentral()
    // Sign whenever a key is configured (CI); local `publishToMavenLocal` works without one.
    if (!providers.gradleProperty("signingInMemoryKey").orNull.isNullOrBlank()) signAllPublications()
    coordinates("com.identvia", "identvia-core", version.toString())
    pom {
        name.set("Identvia Core")
        description.set("Platform-neutral OpenID Connect core for Sign in with Identvia: PKCE, discovery, ID token validation and refresh-token rotation (Kotlin/JVM).")
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
    // Empty javadoc jar (Kotlin sources; Maven Central requires the jar to exist) plus a sources jar.
    configure(com.vanniktech.maven.publish.KotlinJvm(javadocJar = com.vanniktech.maven.publish.JavadocJar.Empty(), sourcesJar = true))
}
