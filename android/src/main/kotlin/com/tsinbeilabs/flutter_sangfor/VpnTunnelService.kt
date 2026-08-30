package com.tsinbeilabs.flutter_sangfor

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.net.VpnService
import io.flutter.Log

/**
 * Foreground VpnService that establishes a TUN interface and hands the raw
 * file descriptor to the Dart side, which reads and writes it directly
 * through FFI. The app's own package is excluded from the VPN so tunnel
 * transport cannot loop back through the TUN interface.
 */
class VpnTunnelService : VpnService() {
    companion object {
        @Volatile
        var activeService: VpnTunnelService? = null
            private set

        private const val CHANNEL_ID = "flutter_sangfor_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TAG = "VpnTunnelService"

        fun start(context: Context) {
            val intent = Intent(context, VpnTunnelService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, VpnTunnelService::class.java))
        }
    }

    override fun onCreate() {
        super.onCreate()
        activeService = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        activeService = null
        super.onDestroy()
    }

    /**
     * Establishes the TUN interface with the given parameters and detaches
     * the file descriptor so Dart owns it. Returns the raw fd or null when
     * the interface could not be established.
     */
    fun establish(
        address: String,
        prefixLength: Int,
        routes: List<String>,
        dnsServers: List<String>,
        searchDomains: List<String>,
        mtu: Int,
    ): Int? {
        val builder = Builder()
            .setSession("flutter_sangfor")
            .addAddress(address, prefixLength)
        if (mtu > 0) {
            builder.setMtu(mtu)
        }
        for (route in routes) {
            val separator = route.lastIndexOf('/')
            if (separator <= 0) continue
            val prefix = route.substring(0, separator)
            val length = route.substring(separator + 1).toIntOrNull() ?: continue
            builder.addRoute(prefix, length)
        }
        for (dns in dnsServers) {
            builder.addDnsServer(dns)
        }
        for (domain in searchDomains) {
            builder.addSearchDomain(domain)
        }
        try {
            // Keep the app's own traffic (the tunnel transport) out of the
            // VPN to avoid routing loops.
            builder.addDisallowedApplication(packageName)
        } catch (error: PackageManager.NameNotFoundException) {
            Log.w(TAG, "addDisallowedApplication failed", error)
        }
        val descriptor: ParcelFileDescriptor = builder.establish() ?: return null
        return descriptor.detachFd()
    }

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            if (manager.getNotificationChannel(CHANNEL_ID) == null) {
                manager.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        "VPN",
                        NotificationManager.IMPORTANCE_LOW,
                    )
                )
            }
        }
        @Suppress("DEPRECATION")
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("VPN active")
            .setContentText("flutter_sangfor tunnel is running")
            .setOngoing(true)
            .build()
    }
}
