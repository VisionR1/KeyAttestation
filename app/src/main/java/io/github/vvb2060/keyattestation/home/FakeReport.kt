package io.github.vvb2060.keyattestation.home

/*
 * Entertainment-only display override.
 *
 * This object holds the in-memory state that makes the home screen render a simulated
 * report. Nothing here touches the certificate chain, the keystore, the revocation
 * database or any persisted setting: the value lives in memory, so it is gone as soon as
 * the process dies, and the user menu can always switch it back off.
 *
 * 只伪装用户主动选择的那一项，其余一律跟随真实结果或落到"正常"默认值，
 * 这样只改一项时不会连带把别的项目也弄成异常。
 */
object FakeReport {

    /* ---- 根证书 / keybox：-1 表示跟随真实结果 ------------------------------ */

    const val ROOT_REAL = -1
    const val ROOT_GOOGLE = 0
    const val ROOT_GOOGLE_RKP = 1
    const val ROOT_AOSP = 2
    const val ROOT_KNOX = 3
    const val ROOT_OEM = 4
    const val ROOT_UNKNOWN = 5
    const val ROOT_FAILED = 6
    const val ROOT_NULL = 7

    /* ---- 引导加载状态：-1 表示跟随真实结果 --------------------------------- */

    const val BOOT_REAL = -1
    /** Locked, verified boot. */
    const val BOOT_VERIFIED = 0
    /** Unlocked, verified boot. */
    const val BOOT_UNLOCKED = 1
    /** Locked, self-signed (root of trust set by end user). */
    const val BOOT_SELF_SIGNED = 2
    /** Unlocked, unverified boot. */
    const val BOOT_UNVERIFIED = 3
    /** Locked, verified boot failed. */
    const val BOOT_FAILED = 4
    /** No root of trust at all: the app shows "Bootloader status is unknown". */
    const val BOOT_NO_ROOT = 5

    /* ---- 证书状态：-1 表示跟随真实结果 ------------------------------------- */

    const val CERT_REAL = -1
    const val CERT_OK = 0
    const val CERT_EXPIRED = 1
    const val CERT_REVOKED = 2
    const val CERT_BAD_SIGNATURE = 3

    /* ---- 吊销列表：-1 表示跟随真实结果 ------------------------------------- */

    const val REVOCATION_REAL = -1
    const val REVOCATION_NONE = 0
    const val REVOCATION_PRISTINE = 1

    /* ---- 整个报告 ---------------------------------------------------------- */

    /** Normal report: everything is rendered from the parsed data. */
    const val PAGE_REPORT = 0
    /** Nothing can be parsed: the app shows one of the AttestationException cards. */
    const val PAGE_ERROR = 1

    /** AttestationException.CODE_* values that produce a full error page. */
    val ERROR_CODES = intArrayOf(
        /* CODE_CANT_PARSE_CERT */ 2,
        /* CODE_OUT_OF_KEYS */ 5,
        /* CODE_OUT_OF_KEYS_TRANSIENT */ 6,
        /* CODE_UNAVAILABLE */ 0,
        /* CODE_UNAVAILABLE_TRANSIENT */ 7,
        /* CODE_KEYS_NOT_PROVISIONED */ 8,
        /* CODE_RKP */ 9,
        /* CODE_STRONGBOX_UNAVAILABLE */ 3,
        /* CODE_DEVICEIDS_UNAVAILABLE */ 4,
        /* CODE_ATTEST_RSA_KEY_EC_ONLY */ 10,
        /* CODE_ATTEST_EC_KEY_RSA_ONLY */ 11,
        /* CODE_INVALID_FILE */ 12,
    )

    @Volatile
    var enabled = false

    /** Callbacks used to re-render the visible screen; both are UI only. */
    @Volatile
    var onChanged: (() -> Unit)? = null
    @Volatile
    var onActivityRefresh: (() -> Unit)? = null

    @Volatile
    var rootKind = ROOT_REAL

    @Volatile
    var bootState = BOOT_REAL

    @Volatile
    var certStatus = CERT_REAL

    @Volatile
    var revocation = REVOCATION_REAL

    @Volatile
    var page = PAGE_REPORT

    /** Index into ERROR_CODES when page == PAGE_ERROR. */
    @Volatile
    var errorIndex = 0

    /** Suppresses the software attestation and verified boot key warning cards. */
    @Volatile
    var hideTampering = false

    /** 全部回到"跟随真实结果"，即什么都不伪装。 */
    fun reset() {
        enabled = false
        rootKind = ROOT_REAL
        bootState = BOOT_REAL
        certStatus = CERT_REAL
        revocation = REVOCATION_REAL
        page = PAGE_REPORT
        errorIndex = 0
        hideTampering = false
    }

    /** 开启伪装时调用：保证从"全正常"起步，只改用户选的那一项。 */
    fun resetOverrides() {
        rootKind = ROOT_REAL
        bootState = BOOT_REAL
        certStatus = CERT_REAL
        revocation = REVOCATION_REAL
        page = PAGE_REPORT
        errorIndex = 0
    }

    fun notifyChanged() {
        onChanged?.invoke()
    }

    val hasRootOverride get() = rootKind != ROOT_REAL
    val hasBootOverride get() = bootState != BOOT_REAL

    /** true: locked, false: unlocked, null: the card reports an unknown state. */
    fun locked(): Boolean? = when (bootState) {
        BOOT_VERIFIED, BOOT_SELF_SIGNED -> true
        BOOT_UNLOCKED, BOOT_UNVERIFIED, BOOT_FAILED -> false
        else -> null
    }

    /** Mapped to RootOfTrust.KM_VERIFIED_BOOT_* without importing the class. */
    fun bootStateValue(): Int = when (bootState) {
        BOOT_VERIFIED -> 0
        BOOT_SELF_SIGNED -> 1
        BOOT_UNVERIFIED, BOOT_UNLOCKED -> 2
        BOOT_FAILED -> 3
        else -> 2
    }

    /** true when the only thing missing is the root of trust itself. */
    fun hidesRootOfTrust(): Boolean = bootState == BOOT_NO_ROOT

    fun errorCode(): Int = ERROR_CODES[errorIndex.coerceIn(0, ERROR_CODES.size - 1)]
}
