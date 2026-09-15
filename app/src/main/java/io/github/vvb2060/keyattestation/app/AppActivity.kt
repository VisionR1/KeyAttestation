package io.github.vvb2060.keyattestation.app

import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import android.graphics.Color
import android.os.Build
import androidx.appcompat.app.AppCompatDelegate
import rikka.core.res.resolveColor
import rikka.material.app.MaterialActivity

open class AppActivity : MaterialActivity() {

    override fun attachBaseContext(newBase: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val locales = AppCompatDelegate.getApplicationLocales()
            if (locales.size() > 0) {
                val locale = locales[0]!!
                val config = Configuration(newBase.resources.configuration)
                config.setLocale(locale)
                super.attachBaseContext(newBase.createConfigurationContext(config))
            } else {
                super.attachBaseContext(newBase)
            }
        } else {
            super.attachBaseContext(newBase)
        }
    }

    override fun shouldApplyTranslucentSystemBars(): Boolean {
        return true
    }

    override fun onApplyTranslucentSystemBars() {
        super.onApplyTranslucentSystemBars()

        val window = window
        val theme = theme

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            window?.decorView?.post {
                if (window.decorView.rootWindowInsets?.systemWindowInsetBottom ?: 0 >= Resources.getSystem().displayMetrics.density * 40) {
                    window.navigationBarColor = theme.resolveColor(android.R.attr.navigationBarColor) and 0x00ffffff or -0x20000000
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        window.isNavigationBarContrastEnforced = false
                    }
                } else {
                    window.navigationBarColor = Color.TRANSPARENT
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        window.isNavigationBarContrastEnforced = true
                    }
                }
            }
        }
    }
}