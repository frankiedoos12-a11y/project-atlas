package com.projectatlas.android

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.util.TypedValue
import android.view.View
import android.view.WindowInsets
import android.widget.LinearLayout
import android.widget.TextView

/** Small helpers for building screens in code (no layout files, no libraries). */
fun Activity.dp(value: Int): Int =
    TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), resources.displayMetrics).toInt()

fun Activity.text(value: String, size: Float = 15f, bold: Boolean = false, color: Int? = null): TextView =
    TextView(this).apply {
        text = value
        textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
        color?.let(::setTextColor)
        setTextIsSelectable(false)
    }

fun Activity.column(): LinearLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

/** Draw behind the status and navigation bars, but keep the content clear of them. */
fun Activity.showEdgeToEdge(root: View, padding: Int) {
    if (Build.VERSION.SDK_INT >= 30) {
        window.setDecorFitsSystemWindows(false)
        root.setOnApplyWindowInsetsListener { view, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            view.setPadding(padding + bars.left, padding + bars.top, padding + bars.right, padding + bars.bottom)
            insets
        }
    } else {
        root.setPadding(padding, padding, padding, padding)
    }
    setContentView(root)
}

/** One line in a list: a section heading, or a row you can tap. */
class Line(
    val title: String,
    val detail: String = "",
    val color: Int? = null,
    val heading: Boolean = false,
    val onTap: (() -> Unit)? = null,
)

/** A list of headings and rows, for the screens that show sections. */
class LineAdapter(private val activity: Activity) : android.widget.BaseAdapter() {
    var lines: List<Line> = emptyList()
        set(value) {
            field = value
            notifyDataSetChanged()
        }

    override fun getCount() = lines.size
    override fun getItem(position: Int) = lines[position]
    override fun getItemId(position: Int) = position.toLong()
    override fun isEnabled(position: Int) = lines[position].onTap != null
    override fun getViewTypeCount() = 1

    override fun getView(position: Int, convertView: View?, parent: android.view.ViewGroup): View {
        val line = lines[position]
        val view = (convertView as? LinearLayout) ?: activity.column().apply {
            addView(activity.text("", 16f, bold = true))
            addView(activity.text("", 13f).also { tag = it.textColors }) // the theme's colour, for uncoloured rows
        }
        view.setPadding(0, activity.dp(if (line.heading) 18 else 8), 0, activity.dp(8))
        (view.getChildAt(0) as TextView).apply {
            text = line.title
            textSize = if (line.heading) 18f else 16f
        }
        (view.getChildAt(1) as TextView).apply {
            text = line.detail
            visibility = if (line.detail.isEmpty()) View.GONE else View.VISIBLE
            if (line.color != null) setTextColor(line.color) else setTextColor(view.tag as android.content.res.ColorStateList)
        }
        return view
    }
}

fun Activity.openWeb(address: String) {
    try {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(address)))
    } catch (e: ActivityNotFoundException) {
        // no browser
    }
}
