package host.enclave.dns

import android.content.Intent
import android.net.VpnService
import android.os.Build
import java.io.File

/**
 * A DNS-only VPN: it routes just two addresses into the app, the DNS server
 * it hands Android (10.53.0.1, fd53::1) and the .eth gateway (10.53.0.3).
 * Every other packet takes the normal network. The app itself is left out
 * of the VPN, so its own connections to EnclaveDNS never loop back in.
 */
class EnclaveVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        // a null intent: Android restarting it, or Always-on VPN
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        shutdown()
        val b = Builder()
            .setSession("EnclaveDNS")
            .setMtu(1500)
            .addAddress("10.53.0.2", 32)
            .addAddress("fd53::2", 128)
            .addDnsServer("10.53.0.1")
            .addDnsServer("fd53::1")
            .addRoute("10.53.0.1", 32)
            .addRoute("10.53.0.3", 32)
            .addRoute("fd53::1", 128)
        try {
            b.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        val iface = try {
            b.establish()
        } catch (e: Exception) {
            lastError = "Android refused the VPN: ${e.message}"
            null
        } ?: run {
            if (lastError == null) lastError = "Android refused the VPN (is another VPN always-on?)"
            stopSelf()
            return
        }
        val err = Native.start(iface.detachFd(), Settings(this).toToml(), stateDir(this).path)
        if (err != null) {
            lastError = err
            running = false
            stopSelf()
        } else {
            lastError = null
            running = true
        }
    }

    private fun shutdown() {
        if (running) Native.stop()
        running = false
    }

    override fun onRevoke() {
        shutdown()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "host.enclave.dns.STOP"

        @Volatile var running = false
        @Volatile var lastError: String? = null

        fun stateDir(c: android.content.Context) = File(c.filesDir, "state").apply { mkdirs() }
    }
}
