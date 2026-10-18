package host.enclave.dns

import android.content.Context

/** The user's settings, kept in SharedPreferences and handed to the engine as TOML. */
class Settings(context: Context) {
    private val p = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    var upstream: String
        get() = p.getString("upstream", DEFAULT_UPSTREAM)!!
        set(v) = p.edit().putString("upstream", v.trim()).apply()
    var fallback: Boolean
        get() = p.getBoolean("fallback", true)
        set(v) = p.edit().putBoolean("fallback", v).apply()
    var ipfs: String
        get() = p.getString("ipfs", "http://127.0.0.1:8080")!!
        set(v) = p.edit().putString("ipfs", v.trim()).apply()
    var ipfsApi: String
        get() = p.getString("ipfs_api", "http://127.0.0.1:5001")!!
        set(v) = p.edit().putString("ipfs_api", v.trim()).apply()
    var bee: String
        get() = p.getString("bee", "http://127.0.0.1:1633")!!
        set(v) = p.edit().putString("bee", v.trim()).apply()
    var arweave: String
        get() = p.getString("arweave", "http://127.0.0.1:3000")!!
        set(v) = p.edit().putString("arweave", v.trim()).apply()
    var tor: String
        get() = p.getString("tor", "127.0.0.1:9050")!!
        set(v) = p.edit().putString("tor", v.trim()).apply()

    fun toToml(): String {
        fun q(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        val torList = tor.split(',', ' ').filter { it.isNotBlank() }.joinToString(", ") { q(it) }
        return buildString {
            append("upstream = ${q(upstream)}\n")
            if (!fallback) append("fallback = []\n")
            append("\n[backends]\n")
            append("ipfs = ${q(ipfs)}\n")
            append("ipfs_api = ${q(ipfsApi)}\n")
            append("bee = ${q(bee)}\n")
            append("arweave = ${q(arweave)}\n")
            append("tor = [$torList]\n")
        }
    }

    companion object {
        const val DEFAULT_UPSTREAM = "https://59f1273d.app.enclave.host"
    }
}
