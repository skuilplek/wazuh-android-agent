plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "io.github.hannescoetzee.wazuhagent"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.hannescoetzee.wazuhagent"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.3.0"
    }

    signingConfigs {
        // A real release key, when all four settings are given as Gradle properties or environment variables.
        val release = ReleaseSigning.from(providers)
        if (release != null) {
            create("release") {
                storeFile = file(release.storeFile)
                storePassword = release.storePassword
                keyAlias = release.keyAlias
                keyPassword = release.keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Sideloaded personal build: sign release with the debug key unless a real one is configured.
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

base {
    archivesName = "wazuh-agent-${android.defaultConfig.versionName}"
}

kotlin {
    jvmToolchain(17)
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(project(":protocol"))

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.security.crypto)

    testImplementation(libs.junit)
}

/**
 * Release signing settings. Each one is read from the Gradle property or, failing that, the environment
 * variable of the same name, so CI can pass secrets without writing them to disk in the repo.
 */
data class ReleaseSigning(
    val storeFile: String,
    val storePassword: String,
    val keyAlias: String,
    val keyPassword: String,
) {
    companion object {
        private const val STORE_FILE = "WAZUH_AGENT_STORE_FILE"
        private const val STORE_PASSWORD = "WAZUH_AGENT_STORE_PASSWORD"
        private const val KEY_ALIAS = "WAZUH_AGENT_KEY_ALIAS"
        private const val KEY_PASSWORD = "WAZUH_AGENT_KEY_PASSWORD"

        /** Null unless all four are set; a partial configuration fails the build instead of silently using the debug key. */
        fun from(providers: ProviderFactory): ReleaseSigning? {
            fun setting(name: String): String? =
                (providers.gradleProperty(name).orNull ?: providers.environmentVariable(name).orNull)?.takeIf { it.isNotBlank() }

            val storeFile = setting(STORE_FILE)
            val storePassword = setting(STORE_PASSWORD)
            val keyAlias = setting(KEY_ALIAS)
            val keyPassword = setting(KEY_PASSWORD)
            if (storeFile == null && storePassword == null && keyAlias == null && keyPassword == null) return null
            if (storeFile == null || storePassword == null || keyAlias == null || keyPassword == null) {
                val missing = mapOf(
                    STORE_FILE to storeFile, STORE_PASSWORD to storePassword, KEY_ALIAS to keyAlias, KEY_PASSWORD to keyPassword,
                ).filterValues { it == null }.keys
                throw GradleException("Release signing is partly configured; missing: ${missing.joinToString()}")
            }
            return ReleaseSigning(storeFile, storePassword, keyAlias, keyPassword)
        }
    }
}
