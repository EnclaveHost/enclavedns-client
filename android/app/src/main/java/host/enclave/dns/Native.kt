package host.enclave.dns

/** The Rust engine (android/rust). */
object Native {
    init {
        System.loadLibrary("enclavedns_android")
    }

    /** Start on the VPN's file descriptor (the engine owns it). Null = started, else why not. */
    @JvmStatic external fun start(fd: Int, configToml: String, stateDir: String): String?

    @JvmStatic external fun stop()

    /** JSON: answers, EnclaveDNS reachability, which local software it sees. */
    @JvmStatic external fun status(): String

    /** Null when the settings are valid, else why not. */
    @JvmStatic external fun check(configToml: String): String?

    /** The .eth CA certificate (PEM), made if missing. */
    @JvmStatic external fun caPem(stateDir: String): String?
}
