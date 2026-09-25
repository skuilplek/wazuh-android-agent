package io.github.hannescoetzee.wazuhagent.collectors

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import io.github.hannescoetzee.wazuhagent.queue.EventQueue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Reports the default network whenever its identity changes: transport, VPN, addresses,
 * DNS and (with location permission) the Wi-Fi network name and security type.
 */
class NetworkCollector(
    private val context: Context,
    private val queue: EventQueue,
    private val onNetworkAvailable: () -> Unit,
) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val prefs = context.getSharedPreferences("network_state", Context.MODE_PRIVATE)
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var pending: Job? = null

    @Volatile private var capabilities: NetworkCapabilities? = null
    @Volatile private var link: LinkProperties? = null

    fun register(scope: CoroutineScope) {
        val handler = Handler(scope)
        // Location info (SSID) in callbacks needs the API 31 flag constructor.
        val cb = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && hasLocation()) {
            object : ConnectivityManager.NetworkCallback(ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO) {
                override fun onAvailable(network: Network) = handler.available()
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = handler.capabilities(caps)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = handler.link(lp)
                override fun onLost(network: Network) = handler.lost()
            }
        } else {
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = handler.available()
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = handler.capabilities(caps)
                override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = handler.link(lp)
                override fun onLost(network: Network) = handler.lost()
            }
        }
        cm.registerDefaultNetworkCallback(cb)
        callback = cb
    }

    private inner class Handler(private val scope: CoroutineScope) {
        fun available() = onNetworkAvailable()

        fun capabilities(caps: NetworkCapabilities) {
            capabilities = caps
            schedule(scope)
        }

        fun link(lp: LinkProperties) {
            link = lp
            schedule(scope)
        }

        fun lost() {
            capabilities = null
            link = null
            schedule(scope)
        }
    }

    fun unregister() {
        callback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        callback = null
        pending?.cancel()
    }

    /** Callbacks arrive in bursts on every change; report the settled state once. */
    private fun schedule(scope: CoroutineScope) {
        pending?.cancel()
        pending = scope.launch {
            delay(SETTLE_MS)
            report()
        }
    }

    private suspend fun report() {
        val snapshot = snapshot(capabilities, link)
        val identity = snapshot.toString()
        if (identity == prefs.getString(KEY_LAST, null)) return
        prefs.edit { putString(KEY_LAST, identity) }
        queue.enqueue(Events.build("network") { snapshot.keys().forEach { put(it, snapshot.get(it)) } })
    }

    private fun snapshot(caps: NetworkCapabilities?, lp: LinkProperties?): JSONObject = JSONObject().apply {
        if (caps == null) {
            put("connected", false)
            put("transport", "none")
            return@apply
        }
        val vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        put("connected", true)
        put("transport", transport(caps))
        put("vpn", vpn)
        put("validated", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
        put("metered", !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
        put("captive_portal", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL))
        if (lp != null) {
            put("interface", lp.interfaceName ?: "")
            put("addresses", Events.array(lp.linkAddresses.map { it.address.hostAddress.orEmpty() }.sorted()))
            put("dns_servers", Events.array(lp.dnsServers.map { it.hostAddress.orEmpty() }))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                put("private_dns_active", lp.isPrivateDnsActive)
                put("private_dns_server", lp.privateDnsServerName ?: "")
            }
        }
        put("private_dns_mode", runCatching { Settings.Global.getString(context.contentResolver, "private_dns_mode") }.getOrNull() ?: "")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) putWifi(this, caps)
    }

    private fun putWifi(target: JSONObject, caps: NetworkCapabilities) {
        val info: WifiInfo? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            caps.transportInfo as? WifiInfo
        } else {
            null
        } ?: runCatching {
            @Suppress("DEPRECATION")
            context.applicationContext.getSystemService(WifiManager::class.java).connectionInfo
        }.getOrNull()
        info ?: return

        val ssid = info.ssid?.trim('"')
        if (hasLocation() && !ssid.isNullOrEmpty() && ssid != WifiManager.UNKNOWN_SSID) {
            target.put("wifi_ssid", ssid)
            target.put("wifi_bssid", info.bssid ?: "")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            target.put("wifi_security", securityType(info.currentSecurityType))
        }
        target.put("wifi_frequency_mhz", info.frequency)
    }

    private fun transport(caps: NetworkCapabilities): String = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "vpn_over_wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "vpn_over_cellular"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
        else -> "other"
    }

    private fun securityType(type: Int): String = when (type) {
        WifiInfo.SECURITY_TYPE_OPEN -> "open"
        WifiInfo.SECURITY_TYPE_WEP -> "wep"
        WifiInfo.SECURITY_TYPE_PSK -> "wpa2_psk"
        WifiInfo.SECURITY_TYPE_EAP -> "wpa_eap"
        WifiInfo.SECURITY_TYPE_SAE -> "wpa3_sae"
        WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> "wpa3_eap_192"
        WifiInfo.SECURITY_TYPE_OWE -> "owe"
        WifiInfo.SECURITY_TYPE_WAPI_PSK -> "wapi_psk"
        WifiInfo.SECURITY_TYPE_WAPI_CERT -> "wapi_cert"
        WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE -> "wpa3_eap"
        WifiInfo.SECURITY_TYPE_OSEN -> "osen"
        WifiInfo.SECURITY_TYPE_PASSPOINT_R1_R2 -> "passpoint_r1_r2"
        WifiInfo.SECURITY_TYPE_PASSPOINT_R3 -> "passpoint_r3"
        WifiInfo.SECURITY_TYPE_DPP -> "dpp"
        else -> "unknown"
    }

    private fun hasLocation() =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    private companion object {
        const val KEY_LAST = "last_snapshot"
        const val SETTLE_MS = 3_000L
    }
}
