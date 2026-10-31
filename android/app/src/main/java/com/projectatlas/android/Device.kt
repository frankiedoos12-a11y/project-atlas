package com.projectatlas.android

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.InputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Reads what the phone knows about installed apps. Only looks: it never changes or removes anything. */
object Device {
    /** Every app you installed, or only the named ones (the 15-minute check asks for just the changed apps). */
    fun installedApps(context: Context, only: Set<String>? = null): List<AppFacts> {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
        }
        val packages = if (only != null) {
            only.mapNotNull { name -> packageInfo(pm, name, flags) }
        } else if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
        }
        if (packages.isEmpty()) return emptyList()
        val resolver = context.contentResolver
        val accessibility = packagesIn(Settings.Secure.getString(resolver, "enabled_accessibility_services"))
        val listeners = packagesIn(Settings.Secure.getString(resolver, "enabled_notification_listeners"))
        val admins = (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager)
            .activeAdmins.orEmpty().map { it.packageName }.toSet()
        val withIcons = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
            .map { it.activityInfo.packageName }.toSet()
        return packages.mapNotNull { info ->
            val app = info.applicationInfo ?: return@mapNotNull null
            // Apps that came with the phone are the maker's; Atlas checks what was added.
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0 || info.packageName == context.packageName) {
                return@mapNotNull null
            }
            AppFacts(
                label = app.loadLabel(pm).toString(),
                packageName = info.packageName,
                installer = installer(pm, info.packageName),
                granted = granted(info),
                accessibilityOn = info.packageName in accessibility,
                deviceAdmin = info.packageName in admins,
                notificationAccess = info.packageName in listeners,
                hasIcon = info.packageName in withIcons,
                version = info.versionName ?: "",
                installed = info.firstInstallTime,
                updated = info.lastUpdateTime,
                apkPath = app.sourceDir,
                signers = signers(info),
            )
        }
    }

    private fun packageInfo(pm: PackageManager, name: String, flags: Int): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(name, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getPackageInfo(name, flags)
        }
    } catch (e: PackageManager.NameNotFoundException) {
        null // removed since
    }

    /** SHA-1 of each certificate the app is signed with, upper case: how stalkerware lists name their signers. */
    fun signers(info: PackageInfo): List<String> {
        val certs = if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo?.let { if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory }
        } else {
            @Suppress("DEPRECATION") info.signatures
        }
        return certs.orEmpty().map { sig ->
            MessageDigest.getInstance("SHA-1").digest(sig.toByteArray()).joinToString("") { "%02X".format(it) }
        }
    }

    /** What the threat data says about an app, if anything. */
    fun intel(context: Context, app: AppFacts, sha256: String?): IntelHit? = try {
        IntelStore.get(context).app(app.packageName, app.signers, sha256)
    } catch (e: Exception) {
        null
    }

    /** "pkg/.Service:pkg2/.Other" -> {pkg, pkg2} */
    fun packagesIn(setting: String?): Set<String> =
        setting.orEmpty().split(':').map { it.substringBefore('/') }.filter { it.isNotBlank() }.toSet()

    private fun granted(info: PackageInfo): Set<String> {
        val names = info.requestedPermissions ?: return emptySet()
        val flags = info.requestedPermissionsFlags ?: return emptySet()
        return names.filterIndexed { i, _ -> flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }.toSet()
    }

    fun installer(pm: PackageManager, name: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(name).installingPackageName
        } else {
            @Suppress("DEPRECATION") pm.getInstallerPackageName(name)
        }
    } catch (e: Exception) {
        null
    }
}

fun sha256(stream: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(1 shl 16)
    stream.use {
        while (true) {
            val read = it.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

/** Answers Atlas already has: app fingerprints (until the app updates) and VirusTotal's verdicts. */
class Answers(context: Context) {
    private val prefs = context.getSharedPreferences("answers", Context.MODE_PRIVATE)

    fun fingerprint(app: AppFacts): String? {
        val path = app.apkPath ?: return null
        val key = "apk:${app.packageName}"
        val stamp = "${app.updated}:"
        prefs.getString(key, null)?.takeIf { it.startsWith(stamp) }?.let { return it.removePrefix(stamp) }
        val hash = try {
            sha256(File(path).inputStream())
        } catch (e: Exception) {
            return null
        }
        prefs.edit().putString(key, stamp + hash).apply()
        return hash
    }

    fun report(sha256: String): VtReport? = VtReport.decode(prefs.getString("vt:$sha256", null), System.currentTimeMillis())

    fun save(sha256: String, report: VtReport) {
        prefs.edit().putString("vt:$sha256", report.encode(System.currentTimeMillis())).apply()
    }
}

/** The VirusTotal key, encrypted with a key that never leaves this phone's keystore. */
object ApiKey {
    private const val ALIAS = "atlas-virustotal"
    private const val PREFS = "secret"

    fun load(context: Context): String? {
        val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("vt", null) ?: return null
        return try {
            val bytes = Base64.getDecoder().decode(saved)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secret(), GCMParameterSpec(128, bytes, 0, 12))
            String(cipher.doFinal(bytes, 12, bytes.size - 12))
        } catch (e: Exception) {
            null
        }
    }

    fun save(context: Context, key: String?) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
        if (key.isNullOrBlank()) {
            prefs.remove("vt").apply()
            return
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secret())
        prefs.putString("vt", Base64.getEncoder().encodeToString(cipher.iv + cipher.doFinal(key.trim().toByteArray())))
            .apply()
    }

    private fun secret(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build())
        return generator.generateKey()
    }
}
