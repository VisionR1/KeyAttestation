package io.github.vvb2060.keyattestation.home

import android.content.Context
import androidx.appcompat.app.AlertDialog
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.lang.AttestationException

/**
 * Dialog for the entertainment-only override. Toggle it from the menu; this dialog only
 * lets the user pick which values are shown. Nothing is written to disk.
 */
object FakeReportDialog {

    /** 顶层可见的四个独立伪装项；彼此互不影响。 */
    fun show(context: Context, onApply: () -> Unit) {
        val res = context.resources
        val entries = arrayOf(
            res.getString(R.string.fake_report_keybox_kind),
            res.getString(R.string.fake_report_boot),
            res.getString(R.string.fake_report_cert_section),
            res.getString(R.string.fake_report_page),
        )
        AlertDialog.Builder(context)
            .setTitle(R.string.menu_fake_report)
            .setItems(entries) { _, which ->
                when (which) {
                    0 -> chooseRoot(context, onApply)
                    1 -> chooseBoot(context, onApply)
                    2 -> chooseCert(context, onApply)
                    else -> choosePage(context, onApply)
                }
            }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    /** 根证书 / keybox 类型：与 RootPublicKey.Status 一一对应。 */
    private fun chooseRoot(context: Context, onApply: () -> Unit) {
        val res = context.resources
        choose(
            context,
            R.string.fake_report_keybox_kind,
            arrayOf(
                res.getString(R.string.fake_report_follow_real),
                res.getString(R.string.google_root_cert),
                res.getString(R.string.google_root_cert_rkp),
                res.getString(R.string.aosp_root_cert),
                res.getString(R.string.knox_root_cert),
                res.getString(R.string.oem_root_cert),
                res.getString(R.string.unknown_root_cert),
                res.getString(R.string.cert_chain_not_trusted),
                res.getString(R.string.error_remote_key_provisioning),
            ),
            (FakeReport.rootKind + 1).coerceIn(0, 8)
        ) {
            FakeReport.rootKind = it - 1
            apply(onApply)
        }
    }

    /** 引导加载状态：与 RootOfTrust.KM_VERIFIED_BOOT_* 及"无 root of trust"对应。 */
    private fun chooseBoot(context: Context, onApply: () -> Unit) {
        val res = context.resources
        choose(
            context,
            R.string.fake_report_boot,
            arrayOf(
                res.getString(R.string.fake_report_follow_real),
                res.getString(R.string.bootloader_locked),
                res.getString(R.string.bootloader_unlocked),
                res.getString(R.string.bootloader_user),
                res.getString(R.string.fake_report_boot_unverified),
                res.getString(R.string.fake_report_boot_failed),
                res.getString(R.string.bootloader_unknown),
            ),
            (FakeReport.bootState + 1).coerceIn(0, 6)
        ) {
            FakeReport.bootState = it - 1
            apply(onApply)
        }
    }

    /** 证书状态 + 吊销列表，合并成一个子菜单。 */
    private fun chooseCert(context: Context, onApply: () -> Unit) {
        val res = context.resources
        val entries = arrayOf(
            res.getString(R.string.fake_report_cert_status),
            res.getString(R.string.fake_report_revocation),
        )
        AlertDialog.Builder(context)
            .setTitle(R.string.fake_report_cert_section)
            .setItems(entries) { _, which ->
                if (which == 0) {
                    choose(
                        context,
                        R.string.fake_report_cert_status,
                        arrayOf(
                            res.getString(R.string.fake_report_cert_real),
                            res.getString(R.string.fake_report_cert_ok),
                            res.getString(R.string.fake_report_cert_expired),
                            res.getString(R.string.fake_report_cert_revoked),
                            res.getString(R.string.fake_report_cert_bad_signature),
                        ),
                        (FakeReport.certStatus + 1).coerceIn(0, 4)
                    ) {
                        FakeReport.certStatus = it - 1
                        apply(onApply)
                    }
                } else {
                    choose(
                        context,
                        R.string.fake_report_revocation,
                        arrayOf(
                            res.getString(R.string.fake_report_revocation_real),
                            res.getString(R.string.fake_report_revocation_none),
                            res.getString(R.string.fake_report_revocation_pristine),
                        ),
                        (FakeReport.revocation + 1).coerceIn(0, 2)
                    ) {
                        FakeReport.revocation = it - 1
                        apply(onApply)
                    }
                }
            }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    /** 整页状态：正常报告，或任一个 AttestationException 错误页。 */
    private fun choosePage(context: Context, onApply: () -> Unit) {
        val res = context.resources
        val codes = FakeReport.ERROR_CODES
        val entries = Array(codes.size + 1) { i ->
            if (i == 0) res.getString(R.string.fake_report_page_report)
            else res.getString(errorTitle(codes[i - 1]))
        }
        val checked = if (FakeReport.page == FakeReport.PAGE_ERROR) FakeReport.errorIndex + 1 else 0
        AlertDialog.Builder(context)
            .setTitle(R.string.fake_report_page)
            .setSingleChoiceItems(entries, checked) { dialog, which ->
                FakeReport.page = if (which == 0) FakeReport.PAGE_REPORT else FakeReport.PAGE_ERROR
                if (which > 0) FakeReport.errorIndex = which - 1
                dialog.dismiss()
                apply(onApply)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun errorTitle(code: Int): Int =
        AttestationException(code, null).titleResId

    private fun apply(onApply: () -> Unit) {
        onApply()
        FakeReport.onActivityRefresh?.invoke()
    }

    private fun choose(
        context: Context,
        titleRes: Int,
        entries: Array<String>,
        checked: Int,
        onChosen: (Int) -> Unit
    ) {
        AlertDialog.Builder(context)
            .setTitle(titleRes)
            .setSingleChoiceItems(entries, checked.coerceIn(0, entries.size - 1)) { dialog, which ->
                onChosen(which)
                dialog.dismiss()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
