package io.github.hannescoetzee.wazuhagent.admin

import android.Manifest
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.CancellationSignal
import androidx.core.content.ContextCompat
import io.github.hannescoetzee.wazuhagent.collectors.Events
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import org.json.JSONObject
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.resume

/**
 * Device Owner containment. Unknown `#!-execd` commands are ignored, and nothing here
 * starts a shell. A personal-phone device admin cannot call these APIs.
 */
object DeviceCommands {
    private val lock = Mutex()

    /**
     * Undoes a locate grant that did not finish, for example because the process was killed
     * after the permission was granted. A grant the user already had is left as it was.
     */
    fun restoreInterruptedLocate(context: Context) {
        if (!DeviceOwner.isDeviceOwner(context)) return
        val prefs = locatePrefs(context)
        val saved = prefs.getString(KEY_LOCATE, null)?.let { runCatching { JSONObject(it) }.getOrNull() }
        if (saved != null) runCatching { restoreLocate(context, saved) }
        if (prefs.contains(KEY_LOCATE)) prefs.edit().remove(KEY_LOCATE).commit()
    }

    suspend fun handle(context: Context, queue: EventQueue, payload: String) = lock.withLock {
        val request = parseExec(payload) ?: return@withLock
        if (request.command !in DEVICE_COMMANDS) return@withLock
        if (!DeviceOwner.isDeviceOwner(context)) {
            queue.enqueue(response(request.command, "denied", "Not device owner", null))
            return@withLock
        }
        if (request.command == "android-wipe") {
            wipe(context, queue, request)
            return@withLock
        }
        val outcome = try {
            run(context, queue, request)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            CommandOutcome("error", e.message ?: e.javaClass.simpleName, packageNameFrom(request.extraArgs, request.alert))
        }
        queue.enqueue(response(request.command, outcome.result, outcome.detail, outcome.packageName))
    }

    private suspend fun wipe(context: Context, queue: EventQueue, request: ExecRequest) {
        if (WIPE_CONFIRM !in request.extraArgs) {
            queue.enqueue(response(request.command, "denied", "Wipe requires extra arg $WIPE_CONFIRM", null))
            return
        }
        queue.enqueue(response(request.command, "ok", "Factory reset starting", null))
        delay(WIPE_DELAY_MS)
        try {
            val dpm = context.getSystemService(android.app.admin.DevicePolicyManager::class.java)
            dpm.wipeData(android.app.admin.DevicePolicyManager.WIPE_EXTERNAL_STORAGE)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            queue.enqueue(response(request.command, "error", e.message ?: "Wipe failed", null))
        }
    }

    private suspend fun run(context: Context, queue: EventQueue, request: ExecRequest): CommandOutcome {
        val packageName = packageNameFrom(request.extraArgs, request.alert)
        return when (request.command) {
            "android-lock" -> lock(context, request.extraArgs)
            "android-locate" -> locate(context, queue)
            "android-suspend" -> changePackage(context, packageName) { dpm, admin, name ->
                val failed = dpm.setPackagesSuspended(admin, arrayOf(name), true)
                if (failed.isEmpty()) ok("Suspended $name", name) else error("Could not suspend $name", name)
            }
            "android-unsuspend" -> changePackage(context, packageName) { dpm, admin, name ->
                val failed = dpm.setPackagesSuspended(admin, arrayOf(name), false)
                if (failed.isEmpty()) ok("Unsuspended $name", name) else error("Could not unsuspend $name", name)
            }
            "android-hide" -> changePackage(context, packageName) { dpm, admin, name ->
                if (dpm.setApplicationHidden(admin, name, true)) ok("Hid $name", name) else error("Could not hide $name", name)
            }
            "android-unhide" -> changePackage(context, packageName) { dpm, admin, name ->
                if (dpm.setApplicationHidden(admin, name, false)) ok("Unhid $name", name) else error("Could not unhide $name", name)
            }
            "android-clear" -> changePackage(context, packageName) { dpm, admin, name ->
                clearData(context, dpm, admin, name)
            }
            "android-uninstall" -> changePackage(context, packageName) { _, _, name -> uninstall(context, name) }
            else -> CommandOutcome("error", "Unknown command", packageName)
        }
    }

    private fun lock(context: Context, extraArgs: List<String>): CommandOutcome {
        val dpm = context.getSystemService(android.app.admin.DevicePolicyManager::class.java)
        val admin = AgentDeviceAdminReceiver.component(context)
        dpm.setDeviceOwnerLockScreenInfo(admin, lockMessage(extraArgs))
        dpm.lockNow()
        return ok("Device locked", null)
    }

    private suspend fun locate(context: Context, queue: EventQueue): CommandOutcome {
        val dpm = context.getSystemService(android.app.admin.DevicePolicyManager::class.java)
        val admin = AgentDeviceAdminReceiver.component(context)
        val fine = Manifest.permission.ACCESS_FINE_LOCATION
        val coarse = Manifest.permission.ACCESS_COARSE_LOCATION
        val granted = android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        val previousFine = dpm.getPermissionGrantState(admin, context.packageName, fine)
        val previousCoarse = dpm.getPermissionGrantState(admin, context.packageName, coarse)
        val locations = context.getSystemService(LocationManager::class.java)
        val wasEnabled = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) locations.isLocationEnabled else true
        locatePrefs(context).edit()
            .putString(
                KEY_LOCATE,
                JSONObject()
                    .put("fine", previousFine)
                    .put("coarse", previousCoarse)
                    .put("location_was_enabled", wasEnabled)
                    .toString(),
            )
            .commit()
        if (previousFine != granted) dpm.setPermissionGrantState(admin, context.packageName, fine, granted)
        if (previousCoarse != granted) dpm.setPermissionGrantState(admin, context.packageName, coarse, granted)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && !wasEnabled) dpm.setLocationEnabled(admin, true)
        return try {
            val fixes = readFixes(context, locations)
            fixes.forEach { queue.enqueue(it) }
            if (fixes.isEmpty()) error("No location fix", null) else ok("Sent ${fixes.size} location events", null)
        } finally {
            runCatching { restoreLocate(context, previousFine, previousCoarse, wasEnabled) }
            locatePrefs(context).edit().remove(KEY_LOCATE).commit()
        }
    }

    private fun restoreLocate(context: Context, saved: JSONObject) {
        restoreLocate(
            context,
            saved.optInt("fine", android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT),
            saved.optInt("coarse", android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT),
            saved.optBoolean("location_was_enabled", true),
        )
    }

    private fun restoreLocate(context: Context, previousFine: Int, previousCoarse: Int, locationWasEnabled: Boolean) {
        val dpm = context.getSystemService(android.app.admin.DevicePolicyManager::class.java)
        val admin = AgentDeviceAdminReceiver.component(context)
        val granted = android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && !locationWasEnabled) {
            runCatching { dpm.setLocationEnabled(admin, false) }
        }
        if (previousFine != granted) {
            runCatching { dpm.setPermissionGrantState(admin, context.packageName, Manifest.permission.ACCESS_FINE_LOCATION, previousFine) }
        }
        if (previousCoarse != granted) {
            runCatching { dpm.setPermissionGrantState(admin, context.packageName, Manifest.permission.ACCESS_COARSE_LOCATION, previousCoarse) }
        }
    }

    private fun locatePrefs(context: Context) = context.getSharedPreferences(LOCATE_PREFS, Context.MODE_PRIVATE)

    private suspend fun changePackage(
        context: Context,
        packageName: String?,
        block: suspend (android.app.admin.DevicePolicyManager, android.content.ComponentName, String) -> CommandOutcome,
    ): CommandOutcome {
        if (packageName == null) return error("Package name missing", null)
        if (packageName == context.packageName) return CommandOutcome("denied", "Refusing to change the agent", packageName)
        val dpm = context.getSystemService(android.app.admin.DevicePolicyManager::class.java)
        return block(dpm, AgentDeviceAdminReceiver.component(context), packageName)
    }

    private suspend fun clearData(
        context: Context,
        dpm: android.app.admin.DevicePolicyManager,
        admin: android.content.ComponentName,
        packageName: String,
    ): CommandOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return error("Clearing app data requires Android 9", packageName)
        val succeeded = suspendCancellableCoroutine { cont ->
            dpm.clearApplicationUserData(admin, packageName, context.mainExecutor) { _, ok ->
                if (cont.isActive) cont.resume(ok)
            }
        }
        return if (succeeded) ok("Cleared data for $packageName", packageName) else error("Could not clear $packageName", packageName)
    }

    private suspend fun uninstall(context: Context, packageName: String): CommandOutcome {
        val action = "${context.packageName}.UNINSTALL_RESULT"
        var receiver: BroadcastReceiver? = null
        val status = try {
            withTimeoutOrNull(UNINSTALL_TIMEOUT_MS) {
                suspendCancellableCoroutine { cont ->
                    val waiting = object : BroadcastReceiver() {
                        override fun onReceive(ctx: Context, intent: Intent) {
                            val code = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
                            val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
                            if (cont.isActive) cont.resume(code to message)
                        }
                    }
                    receiver = waiting
                    ContextCompat.registerReceiver(context, waiting, IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED)
                    cont.invokeOnCancellation { runCatching { context.unregisterReceiver(waiting) } }
                    // The system writes the status into this intent, which an immutable PendingIntent drops.
                    val mutable = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
                    val pending = PendingIntent.getBroadcast(
                        context,
                        0,
                        Intent(action).setPackage(context.packageName),
                        PendingIntent.FLAG_UPDATE_CURRENT or mutable,
                    )
                    try {
                        context.packageManager.packageInstaller.uninstall(packageName, pending.intentSender)
                    } catch (e: Exception) {
                        if (e is CancellationException) throw e
                        if (cont.isActive) cont.resume(PackageInstaller.STATUS_FAILURE to (e.message ?: "Uninstall failed"))
                    }
                }
            }
        } finally {
            receiver?.let { runCatching { context.unregisterReceiver(it) } }
        }
        if (status == null) return error("Uninstall timed out", packageName)
        val (code, message) = status
        return when (code) {
            PackageInstaller.STATUS_SUCCESS -> ok("Uninstalled $packageName", packageName)
            PackageInstaller.STATUS_PENDING_USER_ACTION -> error("Uninstall needs a confirmation on the phone", packageName)
            else -> error(message.ifBlank { "Uninstall status $code" }, packageName)
        }
    }

    private suspend fun readFixes(context: Context, locations: LocationManager): List<org.json.JSONObject> {
        val last = providers(locations).firstNotNullOfOrNull { provider ->
            runCatching { locations.getLastKnownLocation(provider) }.getOrNull()
        }
        val current = currentFix(context, locations)
        return listOfNotNull(last, current)
            .distinctBy { it.time }
            .map { locationEvent(it) }
    }

    private suspend fun currentFix(context: Context, locations: LocationManager): Location? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        val provider = providers(locations).firstOrNull() ?: return null
        return withTimeoutOrNull(CURRENT_FIX_MS) {
            suspendCancellableCoroutine { cont ->
                val signal = CancellationSignal()
                cont.invokeOnCancellation { signal.cancel() }
                try {
                    locations.getCurrentLocation(provider, signal, context.mainExecutor) { location ->
                        if (cont.isActive) cont.resume(location)
                    }
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    if (cont.isActive) cont.resume(null)
                }
            }
        }
    }

    private fun providers(locations: LocationManager): List<String> {
        val names = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) names += LocationManager.FUSED_PROVIDER
        names += LocationManager.GPS_PROVIDER
        names += LocationManager.NETWORK_PROVIDER
        return names.filter { runCatching { locations.isProviderEnabled(it) }.getOrDefault(false) }
    }

    private fun locationEvent(location: Location) = Events.build("location") {
        put("latitude", location.latitude)
        put("longitude", location.longitude)
        put("accuracy_m", location.accuracy.toInt())
        put("provider", location.provider ?: "")
        put("command", "android-locate")
    }

    private fun response(command: String, result: String, detail: String, packageName: String?) = Events.build("response") {
        put("command", command)
        put("result", result)
        put("detail", detail)
        if (!packageName.isNullOrEmpty()) put("package", packageName)
    }

    private fun ok(detail: String, packageName: String?) = CommandOutcome("ok", detail, packageName)

    private fun error(detail: String, packageName: String?) = CommandOutcome("error", detail, packageName)

    private data class CommandOutcome(val result: String, val detail: String, val packageName: String?)

    private const val WIPE_DELAY_MS = 3_000L
    private const val UNINSTALL_TIMEOUT_MS = 60_000L
    private const val CURRENT_FIX_MS = 20_000L
    private const val LOCATE_PREFS = "device_commands"
    private const val KEY_LOCATE = "locate_restore"
}
