import org.gradle.plugins.signing.SigningExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Base64

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlinx.serialization)
    alias(libs.plugins.dokka)
    alias(libs.plugins.vanniktech.maven.publish)
    alias(libs.plugins.detekt)
    alias(libs.plugins.ktlint)
}

allprojects {
    if (version == "unspecified") {
        version = "0.1.0-SNAPSHOT"
    }
    group = "pw.binom.ldap"

    repositories {
        mavenLocal()
        google()
        mavenCentral()
    }
}

kotlin {
    jvm {
        compilations.all {
            compileTaskProvider.configure {
                compilerOptions.jvmTarget.set(JvmTarget.JVM_1_8)
            }
        }
    }
    linuxX64()
    mingwX64()
    macosArm64()
    iosArm64()
    iosSimulatorArm64()
    iosX64()

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.io.core)
            api(libs.kotlinx.io.bytestring)
            api(libs.kotlinx.atomicfu)
            api(libs.ktor.network)
            api(libs.ktor.network.tls)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        jvmTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.testcontainers.junit)
            implementation(libs.junit.jupiter)
        }
    }
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true)
    signAllPublications()
    coordinates(
        groupId = "pw.binom.ldap",
        artifactId = "kldap",
        version = project.version.toString(),
    )

    pom {
        name.set("kldap")
        description.set("Kotlin Multiplatform LDAP client")
        url.set("https://github.com/caffeine-mgn/kldap")

        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("caffeine-mgn")
                name.set("Anton")
                email.set("caffeine.mgn@gmail.com")
            }
        }
        scm {
            connection.set("scm:git:git://github.com/caffeine-mgn/kldap.git")
            developerConnection.set("scm:git:ssh://git@github.com/caffeine-mgn/kldap.git")
            url.set("https://github.com/caffeine-mgn/kldap")
        }
    }
}

detekt {
    config.setFrom("config/detekt/detekt.yml")
}

dokka {
    moduleName.set("kldap")
}

pluginManager.withPlugin("signing") {
    val useGpg = providers.gradleProperty("signingUseGpg").orNull?.toBoolean() ?: false
    if (useGpg) {
        logger.lifecycle("[signing] Using gpg command-line tool")
        extensions.getByType(SigningExtension::class.java).useGpgCmd()
    }
    val key = providers.gradleProperty("signingInMemoryKey").orNull
    val keyId = providers.gradleProperty("signingInMemoryKeyId").orNull
    val password = providers.gradleProperty("signingInMemoryKeyPassword").orNull
    val isBase64 = providers.gradleProperty("signingInMemoryKeyIsBase64").orNull?.toBoolean() ?: false

    if (key != null && keyId != null && password != null) {
        val decodedKey =
            if (isBase64) {
                String(Base64.getDecoder().decode(key))
            } else {
                key.replace("\\n", "\n")
            }
        logger.lifecycle("[signing] Using in-memory PGP key, length=${decodedKey.length}, isBase64=$isBase64")
        extensions
            .getByType(SigningExtension::class.java)
            .useInMemoryPgpKeys(decodedKey, keyId, password)
    }
}
