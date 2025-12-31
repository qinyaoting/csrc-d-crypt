plugins {
    kotlin("jvm") version "2.0.21"
    kotlin("plugin.serialization") version "1.9.0"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.0")
    implementation("com.fazecast:jSerialComm:2.10.4")
}

tasks.test {
    useJUnitPlatform()
}