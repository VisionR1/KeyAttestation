package io.github.vvb2060.keyattestation.home

import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.databinding.HomeHeaderBinding
import rikka.core.res.resolveColorStateList

class HeaderViewHolder(itemView: View, binding: HomeHeaderBinding) : HomeViewHolder<HeaderData, HomeHeaderBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<HeaderData> { inflater, parent ->
            val binding = HomeHeaderBinding.inflate(inflater, parent, false)
            HeaderViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        binding.apply {
            val context = root.context
            root.backgroundTintList = context.theme.resolveColorStateList(data.color)
            icon.setImageDrawable(context.getDrawable(data.icon))
            title.setText(data.title)
            if (data.description != 0) {
                summary.text = context.getString(data.description, *data.formatArgs)
                summary.isVisible = true
            } else {
                summary.isVisible = false
            }
        }
    }
}