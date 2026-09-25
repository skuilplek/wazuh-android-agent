plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    testImplementation(libs.junit)
}

tasks.test {
    // Integration tests against a live manager run only when WAZUH_MANAGER is set.
    listOf("WAZUH_MANAGER", "WAZUH_PASSWORD", "WAZUH_GROUP", "WAZUH_AGENT_NAME", "WAZUH_AGENT_VERSION", "WAZUH_ENROLL_PORT", "WAZUH_PORT")
        .forEach { environment(it, System.getenv(it) ?: "") }
    outputs.upToDateWhen { System.getenv("WAZUH_MANAGER").isNullOrEmpty() }
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
