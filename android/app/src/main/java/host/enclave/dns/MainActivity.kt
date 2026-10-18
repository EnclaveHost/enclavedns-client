package host.enclave.dns

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings as AndroidSettings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject

/**
 * One screen: on/off, what the client is doing, the .eth certificate, and
 * where local IPFS/Swarm/Arweave/Tor software is.
 */
class MainActivity : Activity() {
    private lateinit var settings: Settings
    private lateinit var toggle: Button
    private lateinit var state: TextView
    private lateinit var detail: TextView
    private lateinit var warning: TextView
    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            refresh()
            ui.postDelayed(this, 2000)
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun heading(t: String) = TextView(this).apply {
        text = t
        textSize = 18f
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, dp(20), 0, dp(6))
    }

    private fun para(t: String) = TextView(this).apply {
        text = t
        textSize = 14f
        setPadding(0, dp(2), 0, dp(6))
    }

    private fun field(label: String, value: String, uri: Boolean = true): EditText {
        root.addView(TextView(this).apply { text = label; textSize = 13f; setPadding(0, dp(8), 0, 0) })
        return EditText(this).apply {
            setText(value)
            isSingleLine = true
            inputType = if (uri) InputType.TYPE_TEXT_VARIATION_URI else InputType.TYPE_CLASS_TEXT
            root.addView(this)
        }
    }

    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settings = Settings(this)
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(32))
        }
        root.addView(TextView(this).apply {
            text = "EnclaveDNS"
            textSize = 28f
            setTypeface(typeface, Typeface.BOLD)
        })
        root.addView(para("This phone's DNS through EnclaveDNS: answers checked with DNSSEC inside an attested enclave, and .eth names opened in the browser."))

        state = TextView(this).apply { textSize = 20f; setPadding(0, dp(12), 0, dp(4)) }
        root.addView(state)
        detail = para("")
        root.addView(detail)
        warning = para("").apply { setTextColor(0xFFB45309.toInt()); visibility = View.GONE }
        root.addView(warning)
        toggle = Button(this).apply { setOnClickListener { onToggle() } }
        root.addView(toggle)

        root.addView(heading(".eth sites over HTTPS"))
        root.addView(para("Many .eth sites need HTTPS. The app makes a certificate authority that exists only on this phone and can only vouch for .eth and .ens names. Save it, then install it in Android's settings: Security → Encryption & credentials → Install a certificate → CA certificate."))
        root.addView(Button(this).apply {
            text = "Save the .eth certificate"
            setOnClickListener { saveCertificate() }
        })
        root.addView(Button(this).apply {
            text = "Open security settings"
            setOnClickListener {
                startActivity(Intent(AndroidSettings.ACTION_SECURITY_SETTINGS))
            }
        })

        root.addView(heading("Settings"))
        val upstream = field("EnclaveDNS", settings.upstream)
        val fallback = CheckBox(this).apply {
            text = "Use Quad9 while EnclaveDNS cannot be reached"
            isChecked = settings.fallback
            root.addView(this)
        }
        root.addView(para("Content of .eth sites comes from software you run, never a public gateway. On a phone that is usually a node elsewhere on your network (its gateway must listen on that network)."))
        val ipfs = field("IPFS (kubo) gateway", settings.ipfs)
        val ipfsApi = field("IPFS (kubo) API, for IPNS", settings.ipfsApi)
        val bee = field("Swarm (Bee) API", settings.bee)
        val arweave = field("Arweave (AR.IO) gateway", settings.arweave)
        val tor = field("Tor SOCKS (Orbot: 127.0.0.1:9050)", settings.tor, uri = false)
        root.addView(Button(this).apply {
            text = "Save settings"
            setOnClickListener {
                val old = arrayOf(settings.upstream, settings.fallback, settings.ipfs, settings.ipfsApi, settings.bee, settings.arweave, settings.tor)
                settings.upstream = upstream.text.toString()
                settings.fallback = fallback.isChecked
                settings.ipfs = ipfs.text.toString()
                settings.ipfsApi = ipfsApi.text.toString()
                settings.bee = bee.text.toString()
                settings.arweave = arweave.text.toString()
                settings.tor = tor.text.toString()
                val err = Native.check(settings.toToml())
                if (err != null) {
                    settings.upstream = old[0] as String; settings.fallback = old[1] as Boolean
                    settings.ipfs = old[2] as String; settings.ipfsApi = old[3] as String
                    settings.bee = old[4] as String; settings.arweave = old[5] as String; settings.tor = old[6] as String
                    AlertDialog.Builder(this@MainActivity).setTitle("Not saved").setMessage(err).setPositiveButton("OK", null).show()
                } else if (EnclaveVpnService.running) {
                    startService(Intent(this@MainActivity, EnclaveVpnService::class.java))
                }
            }
        })
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onResume() {
        super.onResume()
        ui.post(tick)
    }

    override fun onPause() {
        super.onPause()
        ui.removeCallbacks(tick)
    }

    private fun onToggle() {
        if (EnclaveVpnService.running) {
            startService(Intent(this, EnclaveVpnService::class.java).setAction(EnclaveVpnService.ACTION_STOP))
            ui.postDelayed({ refresh() }, 300)
            return
        }
        val ask = VpnService.prepare(this)
        if (ask != null) startActivityForResult(ask, REQ_VPN) else startVpn()
    }

    private fun startVpn() {
        startService(Intent(this, EnclaveVpnService::class.java))
        ui.postDelayed({ refresh() }, 500)
    }

    @Deprecated("platform API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when {
            requestCode == REQ_VPN && resultCode == RESULT_OK -> startVpn()
            requestCode == REQ_SAVE_CA && resultCode == RESULT_OK -> data?.data?.let { uri ->
                val pem = Native.caPem(EnclaveVpnService.stateDir(this).path)
                if (pem != null) {
                    contentResolver.openOutputStream(uri)?.use { it.write(pem.toByteArray()) }
                    AlertDialog.Builder(this)
                        .setTitle("Certificate saved")
                        .setMessage("Now install it: Security → Encryption & credentials → Install a certificate → CA certificate, and pick the file you just saved.\n\nIt can only vouch for .eth and .ens names.")
                        .setPositiveButton("Open settings") { _, _ -> startActivity(Intent(AndroidSettings.ACTION_SECURITY_SETTINGS)) }
                        .setNegativeButton("Later", null)
                        .show()
                }
            }
        }
    }

    private fun saveCertificate() {
        val i = Intent(Intent.ACTION_CREATE_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE)
            .setType("application/x-x509-ca-cert")
            .putExtra(Intent.EXTRA_TITLE, "enclavedns-eth-ca.crt")
        startActivityForResult(i, REQ_SAVE_CA)
    }

    /** Android's Private DNS in "hostname" mode sends DNS around any VPN. */
    private fun privateDnsStrict(): Boolean {
        if (Build.VERSION.SDK_INT < 28) return false
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        val lp = cm.getLinkProperties(cm.activeNetwork) ?: return false
        return lp.isPrivateDnsActive && lp.privateDnsServerName != null
    }

    private fun refresh() {
        val on = EnclaveVpnService.running
        toggle.text = if (on) "Turn off" else "Turn on"
        state.text = if (on) "On" else "Off"
        state.gravity = Gravity.START
        val err = EnclaveVpnService.lastError
        detail.text = when {
            err != null -> "Could not start: $err"
            !on -> "This phone's DNS goes where it always did."
            else -> try {
                val s = JSONObject(Native.status())
                val q = s.getJSONObject("queries")
                val b = s.getJSONObject("backends")
                val sites = b.keys().asSequence().joinToString(", ") { k ->
                    "$k " + if (b.getJSONObject(k).optBoolean("detected")) "yes" else "no"
                }
                val reach = if (s.optBoolean("upstream_reachable", true)) "reachable" else "UNREACHABLE (using the fallback)"
                "EnclaveDNS $reach\n" +
                    "${q.optLong("enclavedns")} answers from EnclaveDNS, ${q.optLong("cached")} from cache, " +
                    "${q.optLong("fallback")} from the fallback, ${q.optLong("failed")} failed\n" +
                    ".eth sites: $sites"
            } catch (e: Exception) {
                "status unavailable: ${e.message}"
            }
        }
        if (privateDnsStrict()) {
            warning.text = "Android's Private DNS is set to a hostname, which sends DNS around EnclaveDNS. Set it to Off or Automatic: Settings → Network & internet → Private DNS."
            warning.visibility = View.VISIBLE
            warning.setOnClickListener { startActivity(Intent(AndroidSettings.ACTION_WIRELESS_SETTINGS)) }
        } else {
            warning.visibility = View.GONE
        }
    }

    companion object {
        private const val REQ_VPN = 1
        private const val REQ_SAVE_CA = 2
    }
}
