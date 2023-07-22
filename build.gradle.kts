plugins {
    id("java")
}

group = "bot.inker.ankhguard"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("commons-net:commons-net:3.9.0")

    implementation("org.keycloak:keycloak-dependencies-server-all:22.0.1")

    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}