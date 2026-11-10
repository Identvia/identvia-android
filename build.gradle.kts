plugins {
    id("com.android.library") version "8.5.2" apply false
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.jvm") version "2.0.21" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.0.21" apply false
    // Maven Central (Central Portal) publishing + GPG signing. 0.34.x is the newest line that supports Gradle 8.10 / AGP 8.5.
    id("com.vanniktech.maven.publish") version "0.34.0" apply false
}

allprojects {
    group = "com.identvia"
    version = "0.1.3"
}
