package io.github.vvb2060.keyattestation.util

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.annotation.StyleRes
import androidx.appcompat.app.AlertDialog
import io.github.vvb2060.keyattestation.R

object ColorManager {

    private const val PREFS_NAME = "color_prefs"
    private const val KEY_THEME = "theme_id"

    fun showColorPickerDialog(activity: Activity) {
        val entries = buildList {
            add(R.string.color_default_gray to R.style.Theme_Default_Gray)
            add(R.string.color_original to R.style.Theme_Original)
            add(R.string.color_pure_black to R.style.Theme_Pure_Black)
            add(R.string.color_blue to R.style.Theme_Blue)
            add(R.string.color_green to R.style.Theme_Green)
            add(R.string.color_orange to R.style.Theme_Orange)
            add(R.string.color_pink to R.style.Theme_Pink)
            add(R.string.color_purple to R.style.Theme_Purple)
            add(R.string.color_red to R.style.Theme_Red)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(R.string.color_dynamic to R.style.Theme_Dynamic)
            }
        }
        val colors = Array(entries.size) { activity.getString(entries[it].first) }

        val prefs = getSharedPreferences(activity)
        val savedThemeId = prefs.getInt(KEY_THEME, R.style.Theme_Default_Gray)
        val savedColorIndex = entries.indexOfFirst { it.second == savedThemeId }

        AlertDialog.Builder(activity)
            .setTitle(R.string.menu_color)
            .setSingleChoiceItems(colors, savedColorIndex) { dialog, which ->
                saveTheme(activity, entries[which].second)
                dialog.dismiss()
                activity.recreate()
            }
            .show()
    }

    private fun getSharedPreferences(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private fun saveTheme(context: Context, @StyleRes themeId: Int) {
        getSharedPreferences(context).edit()
            .putInt(KEY_THEME, themeId)
            .apply()
    }

    @StyleRes
    fun getThemeResId(context: Context): Int {
        val prefs = getSharedPreferences(context)
        return prefs.getInt(KEY_THEME, R.style.Theme_Default_Gray)
    }
}