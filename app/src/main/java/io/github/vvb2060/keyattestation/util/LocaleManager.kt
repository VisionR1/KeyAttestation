package io.github.vvb2060.keyattestation.util

import android.app.Activity
import android.content.Context
import android.content.res.Resources
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import io.github.vvb2060.keyattestation.R
import java.util.Locale

object LocaleManager {

    private val supportedLocales = listOf(
        Locale("en"),
        Locale("el"),
		Locale("it"),
        Locale("pt", "BR"),
        Locale("uk", "UA"),
        Locale("zh", "CN"),
        Locale("zh", "TW")
    )

    fun getLocaleCodes() = listOf("") + supportedLocales.map {
        if (it.country.isEmpty()) it.language else "${it.language}-${it.country}"
    }

    fun getLocaleDisplayNames(context: Context): List<String> {
        val sys = Resources.getSystem().configuration.locales[0]
        val app = AppCompatDelegate.getApplicationLocales()[0] ?: sys
        return listOf(sys.getDisplayName(sys)) + supportedLocales.map { it.getDisplayName(app) }
            .map { it.replaceFirstChar { c -> c.uppercaseChar() } }
    }

    fun updateLocale(context: Context, code: String): String {
        context.getSharedPreferences("locale_prefs", Context.MODE_PRIVATE)
            .edit().putString("app_locale", code).apply()
        AppCompatDelegate.setApplicationLocales(
            if (code.isEmpty()) LocaleListCompat.getEmptyLocaleList()
            else LocaleListCompat.create(Locale.forLanguageTag(code))
        )
        return code
    }

    fun loadLocale(context: Context): String {
        val code = context.getSharedPreferences("locale_prefs", Context.MODE_PRIVATE)
            .getString("app_locale", "") ?: ""
        return updateLocale(context, code)
    }

    fun showLanguagePickerDialog(context: Context, onLanguageSelected: () -> Unit = {}) {
        val languageCodes = getLocaleCodes()
        val languages = getLocaleDisplayNames(context)
        val currentIndex = languageCodes.indexOf(loadLocale(context)).coerceAtLeast(0)

        AlertDialog.Builder(context)
            .setTitle(R.string.menu_language)
            .setSingleChoiceItems(languages.toTypedArray(), currentIndex) { dialog, which ->
                updateLocale(context, languageCodes[which])
                dialog.dismiss()
                if (context is Activity) context.recreate()
            }
            .show()
    }
}
