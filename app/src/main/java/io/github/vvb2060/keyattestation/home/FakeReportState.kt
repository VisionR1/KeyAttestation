package io.github.vvb2060.keyattestation.home

/**
 * Value object passed from the rendering layer into an [io.github.vvb2060.keyattestation.attestation.Attestation]
 * so that the simulated report can present a chosen boot state and security level.
 *
 * This is a per-render snapshot; nothing here is stored, persisted or fed back into the
 * real attestation data.
 */
class FakeReportState(
    /** true: locked, false: unlocked, null: unknown. */
    private val lockedValue: Boolean?,
    /** One of the RootOfTrust.KM_VERIFIED_BOOT_* constants. */
    private val bootStateValue: Int,
) {
    fun locked(): Boolean? = lockedValue

    fun bootState(): Int = bootStateValue
}
