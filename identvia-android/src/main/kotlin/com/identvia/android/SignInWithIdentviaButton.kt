package com.identvia.android

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.content.res.ColorStateList
import android.util.AttributeSet
import android.util.TypedValue
import android.view.Gravity
import android.widget.Button

/** The branded "Sign in with Identvia" button (light, dark, brand), matching the web button. */
class SignInWithIdentviaButton @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null, defStyle: Int = 0) :
    Button(context, attrs, defStyle) {

    enum class Theme { LIGHT, DARK, BRAND }
    enum class Label { SIGN_IN, CONTINUE, SIGN_UP }

    var theme: Theme = Theme.LIGHT
        set(v) { field = v; apply() }
    var label: Label = Label.SIGN_IN
        set(v) { field = v; apply() }

    init {
        context.obtainStyledAttributes(attrs, R.styleable.SignInWithIdentviaButton).apply {
            theme = Theme.entries[getInt(R.styleable.SignInWithIdentviaButton_identviaTheme, 0)]
            label = Label.entries[getInt(R.styleable.SignInWithIdentviaButton_identviaText, 0)]
            recycle()
        }
        isAllCaps = false
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        gravity = Gravity.CENTER
        minHeight = dp(40); minimumHeight = dp(40)
        setPadding(dp(16), 0, dp(16), 0)
        compoundDrawablePadding = dp(10)
        setCompoundDrawablesRelativeWithIntrinsicBounds(R.drawable.identvia_mark, 0, 0, 0)
        stateListAnimator = null
        apply()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun apply() {
        val (bg, border, fg) = when (theme) {
            Theme.LIGHT -> Triple(Color.WHITE, 0xFFD4D4D8.toInt(), 0xFF18181B.toInt())
            Theme.DARK -> Triple(0xFF18181B.toInt(), 0xFF3F3F46.toInt(), Color.WHITE)
            Theme.BRAND -> Triple(0xFF4B4ACF.toInt(), 0xFF4B4ACF.toInt(), Color.WHITE)
        }
        val shape = GradientDrawable().apply { cornerRadius = dp(8).toFloat(); setColor(bg); setStroke(dp(1), border) }
        background = RippleDrawable(ColorStateList.valueOf(0x22000000), shape, null)
        setTextColor(fg)
        text = context.getString(when (label) { Label.SIGN_IN -> R.string.identvia_sign_in; Label.CONTINUE -> R.string.identvia_continue; Label.SIGN_UP -> R.string.identvia_sign_up })
        contentDescription = text
    }
}
