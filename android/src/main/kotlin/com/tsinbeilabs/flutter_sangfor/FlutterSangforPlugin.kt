package com.tsinbeilabs.flutter_sangfor

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/** FlutterSangforPlugin */
class FlutterSangforPlugin :
    FlutterPlugin,
    MethodCallHandler,
    ActivityAware {
    private lateinit var channel: MethodChannel
    private var state = "disconnected"
    private var activity: Activity? = null
    private var applicationContext: android.content.Context? = null
    private var pendingPermissionResult: Result? = null

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "flutter_sangfor")
        channel.setMethodCallHandler(this)
        applicationContext = flutterPluginBinding.applicationContext
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        binding.addActivityResultListener { requestCode, resultCode, _ ->
            if (requestCode == VPN_PREPARE_REQUEST_CODE) {
                val result = pendingPermissionResult
                pendingPermissionResult = null
                result?.success(resultCode == Activity.RESULT_OK)
                true
            } else {
                false
            }
        }
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onMethodCall(
        call: MethodCall,
        result: Result,
    ) {
        when (call.method) {
            "getState" -> result.success(state)
            "getCapabilities" -> result.success(
                mapOf(
                    "platform" to "android",
                    "supportsVpn" to true,
                    "supportsTun" to true,
                    "supportsSocks5" to true,
                    "supportedAuthTypes" to emptyList<String>()
                )
            )
            "disconnect" -> {
                state = "disconnected"
                result.success(null)
            }
            "connect" -> result.error(
                "unsupported",
                "The aTrust transport is not implemented on Android yet.",
                null
            )
            "vpnPrepare" -> result.success(VpnService.prepare(activity) == null)
            "vpnRequestPermission" -> {
                val intent = VpnService.prepare(activity)
                if (intent == null) {
                    result.success(true)
                    return
                }
                val currentActivity = activity
                if (currentActivity == null) {
                    result.error("no_activity", "The VPN permission needs a foreground activity.", null)
                    return
                }
                pendingPermissionResult?.error("cancelled", "A newer permission request started.", null)
                pendingPermissionResult = result
                currentActivity.startActivityForResult(intent, VPN_PREPARE_REQUEST_CODE)
            }
            "vpnStart" -> {
                val context = activity?.applicationContext
                if (context == null) {
                    result.error("no_activity", "The VPN service needs an attached activity.", null)
                    return
                }
                VpnTunnelService.start(context)
                // The foreground service takes a moment to come up; establish
                // once it reports itself active.
                val started = waitForService()
                if (!started) {
                    result.error("vpn_start_failed", "The VPN service did not start.", null)
                    return
                }
                val fd = VpnTunnelService.activeService?.establish(
                    call.argument<String>("address") ?: "10.0.0.2",
                    call.argument<Int>("prefixLength") ?: 32,
                    call.argument<List<String>>("routes") ?: emptyList(),
                    call.argument<List<String>>("dnsServers") ?: emptyList(),
                    call.argument<List<String>>("searchDomains") ?: emptyList(),
                    call.argument<Int>("mtu") ?: 0,
                )
                if (fd == null) {
                    result.error("vpn_establish_failed", "VpnService.Builder.establish() returned null.", null)
                    return
                }
                state = "connected"
                result.success(fd)
            }
            "vpnStop" -> {
                val context = activity?.applicationContext ?: applicationContext
                if (context != null) {
                    VpnTunnelService.stop(context)
                }
                state = "disconnected"
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun waitForService(
        timeoutMillis: Long = 5000,
        pollMillis: Long = 25,
    ): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (VpnTunnelService.activeService != null) return true
            Thread.sleep(pollMillis)
        }
        return VpnTunnelService.activeService != null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    companion object {
        private const val VPN_PREPARE_REQUEST_CODE = 7201
    }
}
