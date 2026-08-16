package com.moonlightcloud.app

import android.app.Activity
import android.app.DownloadManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.webkit.CookieManager
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent

// Moonlight Cloud runs entirely inside this WebView, pointed at the site's
// /mobile route. Two things can't happen inside a plain WebView by default,
// and need explicit wiring here: (1) Google sign-in — Google blocks its
// OAuth flow inside embedded WebViews, so that step briefly opens a real
// Chrome Custom Tab (/mobilelogin) and hands the finished session back via a
// moonlightcloud://auth deep link — and (2) <input type="file"> uploads —
// WebView does nothing at all for these unless the app supplies a
// WebChromeClient.onShowFileChooser implementation, which is what launches
// the actual system file picker below.
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private var fileChooserCallback: ValueCallback<Array<Uri>>? = null
    private lateinit var filePickerLauncher: ActivityResultLauncher<Intent>

    companion object {
        const val BASE_URL = "https://moonlight-cloud-fix-production.up.railway.app"
        const val APP_URL = "$BASE_URL/mobile"
        const val LOGIN_PATH = "/mobilelogin"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        filePickerLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val data = result.data
            val results: Array<Uri>? = when {
                result.resultCode != Activity.RESULT_OK || data == null -> null
                data.clipData != null -> {
                    val count = data.clipData!!.itemCount
                    Array(count) { i -> data.clipData!!.getItemAt(i).uri }
                }
                data.data != null -> arrayOf(data.data!!)
                else -> null
            }
            fileChooserCallback?.onReceiveValue(results)
            fileChooserCallback = null
        }

        webView = findViewById(R.id.webView)
        setupWebView()

        // Cold start via the auth deep link (rare, but possible)
        val handledColdStart = intent?.data?.let { handleDeepLink(it) } ?: false
        if (!handledColdStart) {
            webView.loadUrl(APP_URL)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intent.data?.let { handleDeepLink(it) }
    }

    private fun setupWebView() {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            mediaPlaybackRequiresUserGesture = false
        }
        CookieManager.getInstance().setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(webView, true)

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
                if (url.contains(LOGIN_PATH)) {
                    openInCustomTab(url)
                    return true
                }
                return false // everything else stays inside the app
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                webView: WebView,
                filePathCallback: ValueCallback<Array<Uri>>,
                fileChooserParams: FileChooserParams
            ): Boolean {
                fileChooserCallback?.onReceiveValue(null)
                fileChooserCallback = filePathCallback
                val intent = fileChooserParams.createIntent().apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                }
                try {
                    filePickerLauncher.launch(intent)
                } catch (e: Exception) {
                    fileChooserCallback = null
                    Toast.makeText(this@MainActivity, "Couldn't open file picker", Toast.LENGTH_SHORT).show()
                    return false
                }
                return true
            }
        }

        // Standard file downloads (e.g. the raw file link) — hand off to the
        // system Download Manager so they land in the real Downloads folder
        // with a native progress notification.
        webView.setDownloadListener { url, _, contentDisposition, mimeType, _ ->
            try {
                val request = DownloadManager.Request(Uri.parse(url))
                request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                val filename = Uri.parse(url).lastPathSegment ?: "download"
                request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, filename)
                request.setMimeType(mimeType)
                val dm = getSystemService(DOWNLOAD_SERVICE) as DownloadManager
                dm.enqueue(request)
                Toast.makeText(this, "Downloading $filename…", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Couldn't start download", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun openInCustomTab(url: String) {
        val intentBuilder = CustomTabsIntent.Builder()
        val customTabsIntent = intentBuilder.build()
        customTabsIntent.launchUrl(this, Uri.parse(url))
    }

    /** Returns true if [uri] was our auth deep link and was handled. */
    private fun handleDeepLink(uri: Uri): Boolean {
        if (uri.scheme != "moonlightcloud" || uri.host != "auth") return false

        val token = uri.getQueryParameter("token") ?: return false
        val name = uri.getQueryParameter("name") ?: ""
        val email = uri.getQueryParameter("email") ?: ""
        val picture = uri.getQueryParameter("picture") ?: ""

        val target = Uri.parse(APP_URL).buildUpon()
            .appendQueryParameter("token", token)
            .appendQueryParameter("name", name)
            .appendQueryParameter("email", email)
            .appendQueryParameter("picture", picture)
            .build()
            .toString()

        webView.loadUrl(target)
        return true
    }

    override fun onBackPressed() {
        if (webView.canGoBack()) webView.goBack() else super.onBackPressed()
    }
}
