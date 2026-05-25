package com.privet.privet_app

import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.util.Log
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream

class MainActivity : FlutterActivity() {
    companion object {
        private const val REQUEST_PICK_DIRECTORY = 0x1001
    }

    private val CHANNEL = "privet/file"
    private val DEVICE_CHANNEL = "privet/device"
    private val SHARE_CHANNEL = "privet/share"
    private var pendingResult: MethodChannel.Result? = null
    private var shareChannel: MethodChannel? = null
    // Store share data for Dart to pull on cold start (handler may not be ready yet)
    private var pendingShareArgs: Map<String, Any?>? = null

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_PICK_DIRECTORY) {
            val pr = pendingResult
            pendingResult = null
            val uri = data?.data
            if (uri == null) {
                pr?.success(emptyList<String>())
                return
            }
            // Run file copy on background thread to avoid ANR
            Thread {
                try {
                    takePersistableUriPermission(uri.toString())
                    contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                    val docId = DocumentsContract.getTreeDocumentId(uri)
                    val folderName = Uri.decode(docId.substringAfter(':').substringAfterLast('/'))
                    Log.d("PrivetSAF", "pickDirectory docId=$docId folderName=$folderName")
                    val paths = copyDirToCache(uri.toString(), folderName)
                    // MethodChannel result must be delivered on main thread
                    runOnUiThread { pr?.success(paths) }
                } catch (e: Exception) {
                    Log.e("PrivetSAF", "pickDirectory error", e)
                    runOnUiThread { pr?.error("SAF_ERROR", e.message, null) }
                }
            }.start()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShareIntent(intent)
        // Push to Dart immediately (handler is already registered).
        pendingShareArgs?.let { args ->
            runOnUiThread {
                shareChannel?.invokeMethod("onShare", args)
            }
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Share channel — Dart pulls pending data on startup via getPendingShare;
        // onNewIntent deliveries use the onShare push method.
        shareChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, SHARE_CHANNEL).apply {
            setMethodCallHandler { call, result ->
                when (call.method) {
                    "getPendingShare" -> {
                        result.success(pendingShareArgs)
                        pendingShareArgs = null // consumed
                    }
                    else -> result.notImplemented()
                }
            }
        }
        handleShareIntent(intent)

        // Device info channel
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, DEVICE_CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "getDeviceName" -> {
                    val model = android.os.Build.MODEL
                    val manufacturer = android.os.Build.MANUFACTURER
                    result.success("$manufacturer $model")
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "pickDirectory" -> {
                    pendingResult = result
                    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or
                                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
                    }
                    startActivityForResult(intent, REQUEST_PICK_DIRECTORY)
                }
                "copyContentUri" -> {
                    val uri = call.argument<String>("uri") ?: return@setMethodCallHandler
                    try {
                        val inputStream = contentResolver.openInputStream(Uri.parse(uri)) ?: return@setMethodCallHandler
                        val fileName = getFileName(uri)
                            ?: "file_${System.currentTimeMillis()}"
                        val outFile = File(cacheDir, "privet_resend/$fileName")
                        outFile.parentFile?.mkdirs()
                        FileOutputStream(outFile).use { output ->
                            inputStream.use { input -> input.copyTo(output) }
                        }
                        result.success(outFile.absolutePath)
                    } catch (e: Exception) {
                        result.error("COPY_ERROR", e.message, null)
                    }
                }
                "openContentUri" -> {
                    val uri = call.argument<String>("uri") ?: return@setMethodCallHandler
                    try {
                        val intent = Intent(Intent.ACTION_VIEW).apply {
                            setDataAndType(Uri.parse(uri), contentResolver.getType(Uri.parse(uri)))
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        startActivity(intent)
                        result.success(true)
                    } catch (e: Exception) {
                        Log.e("PrivetSAF", "openContentUri failed", e)
                        result.success(false)
                    }
                }
                "checkContentUri" -> {
                    val uri = call.argument<String>("uri") ?: return@setMethodCallHandler result.success(false)
                    try {
                        val fd = contentResolver.openFileDescriptor(Uri.parse(uri), "r")
                        fd?.use { result.success(true) } ?: result.success(false)
                    } catch (_: Exception) {
                        result.success(false)
                    }
                }
                "copyDirectoryToCache" -> {
                    val uri = call.argument<String>("uri") ?: return@setMethodCallHandler result.error("NO_URI", "uri required", null)
                    try {
                        takePersistableUriPermission(uri)
                        val paths = copyDirToCache(uri, "")
                        result.success(paths)
                    } catch (e: Exception) {
                        Log.e("PrivetSAF", "copyDirectoryToCache failed", e)
                        result.error("SAF_ERROR", e.message, null)
                    }
                }
                "readClipboardImage" -> {
                    try {
                        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        val clip = clipboard.primaryClip ?: run { result.success(null); return@setMethodCallHandler }
                        if (clip.itemCount == 0) { result.success(null); return@setMethodCallHandler }
                        val item = clip.getItemAt(0)
                        val uri = item.uri
                        var imageBytes: ByteArray? = null
                        if (uri != null) {
                            try {
                                val inputStream = contentResolver.openInputStream(uri) ?: return@setMethodCallHandler
                                imageBytes = inputStream.use { it.readBytes() }
                            } catch (_: Exception) { }
                        }
                        if (imageBytes == null) {
                            // Try raw data (less common on Android for images)
                            val rawData = try { item.text?.toString()?.toByteArray() } catch (_: Exception) { null }
                            imageBytes = rawData
                        }
                        result.success(imageBytes)
                    } catch (e: Exception) {
                        Log.e("PrivetClip", "readClipboardImage failed", e)
                        result.success(null)
                    }
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun takePersistableUriPermission(uri: String) {
        val parsed = Uri.parse(uri)
        try {
            contentResolver.takePersistableUriPermission(
                parsed,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: Exception) {
            // Not all URIs support persistable permission
        }
    }

    /// Enumerate a SAF tree URI and copy all files to cache (iterative, not recursive).
    /// Returns a list of "absPath|relPath" strings.
    private fun copyDirToCache(treeUri: String, _suffix: String): List<String> {
        val results = mutableListOf<String>()
        // Stack entries: Triple<treeUri, docId, suffix>
        // We always pass the ORIGINAL tree URI (with /tree/) to buildChildDocumentsUriUsingTree
        val rootDocId = DocumentsContract.getTreeDocumentId(Uri.parse(treeUri))
        val stack = ArrayDeque<Triple<String, String, String>>()
        stack.addLast(Triple(treeUri, rootDocId, _suffix))
        val visited = mutableSetOf<String>()

        while (stack.isNotEmpty()) {
            val (currentTreeUri, currentDocId, currentSuffix) = stack.removeLast()
            val visitKey = "$currentTreeUri|$currentDocId"
            if (visitKey in visited) continue
            visited.add(visitKey)

            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
                Uri.parse(currentTreeUri), currentDocId
            )
            Log.d("PrivetSAF", "Query children for docId=$currentDocId suffix=$currentSuffix")
            val cursor = contentResolver.query(childrenUri, null, null, null, null)
            cursor?.use { c ->
                val colMime = c.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val colDocId = c.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val colName = c.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                Log.d("PrivetSAF", "Cursor columns: mime=$colMime docId=$colDocId name=$colName")
                while (c.moveToNext()) {
                    val mimeType = if (colMime >= 0) c.getString(colMime) else null
                    val docId = if (colDocId >= 0) c.getString(colDocId) else null
                    val displayName = if (colName >= 0) c.getString(colName) else docId
                    val finalName = displayName ?: docId ?: "unknown"
                    Log.d("PrivetSAF", "  entry: type=$mimeType name=$finalName docId=$docId")
                    if (DocumentsContract.Document.MIME_TYPE_DIR == mimeType) {
                        val subSuffix = if (currentSuffix.isEmpty()) finalName else "$currentSuffix/$finalName"
                        stack.addLast(Triple(currentTreeUri, docId ?: "unknown", subSuffix))
                    } else {
                        val fileUri = DocumentsContract.buildDocumentUriUsingTree(Uri.parse(currentTreeUri), docId)
                        val relPath = if (currentSuffix.isEmpty()) finalName else "$currentSuffix/$finalName"
                        Log.d("PrivetSAF", "  + file: $relPath uri=$fileUri")
                        val outFile = File(cacheDir, "privet_send/$relPath")
                        outFile.parentFile?.mkdirs()
                        try {
                            contentResolver.openInputStream(fileUri)?.use { input ->
                                FileOutputStream(outFile).use { output -> input.copyTo(output) }
                            }
                            results.add("${outFile.absolutePath}|$relPath")
                        } catch (e: Exception) {
                            Log.w("PrivetSAF", "Failed to copy $relPath: ${e.message}")
                        }
                    }
                }
            }
        }
        return results
    }

    // -----------------------------------------------------------------------
    // Share intent handling (ACTION_SEND / ACTION_SEND_MULTIPLE)
    // -----------------------------------------------------------------------

    /// Process incoming share intent: copy shared files to cache, extract text,
    /// then forward the results to Flutter via the share method channel.
    private fun handleShareIntent(intent: Intent?) {
        if (intent == null) return
        val action = intent.action ?: return

        val paths = mutableListOf<String>()
        var sharedText: String? = null

        try {
            when (action) {
                Intent.ACTION_SEND -> {
                    if (intent.type?.startsWith("text/") == true) {
                        sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    } else {
                        val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                        if (uri != null) {
                            val cached = copyFileToCache(uri)
                            if (cached != null) paths.add(cached)
                        }
                    }
                }
                Intent.ACTION_SEND_MULTIPLE -> {
                    val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
                    if (uris != null) {
                        for (uri in uris) {
                            val cached = copyFileToCache(uri)
                            if (cached != null) paths.add(cached)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("PrivetShare", "handleShareIntent error", e)
        }

        if (paths.isEmpty() && sharedText == null) return

        val args = mutableMapOf<String, Any?>()
        if (paths.isNotEmpty()) args["paths"] = paths
        if (sharedText != null) args["text"] = sharedText

        // Store so Dart can pull via getPendingShare (used on cold start).
        pendingShareArgs = args
    }

    /// Copy a content:// URI to the app cache and return the absolute file path.
    private fun copyFileToCache(uri: Uri): String? {
        return try {
            val fileName = getFileName(uri.toString())
                ?: "shared_${System.currentTimeMillis()}"
            val outFile = File(cacheDir, "privet_share/$fileName")
            outFile.parentFile?.mkdirs()
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(outFile).use { output -> input.copyTo(output) }
            }
            outFile.absolutePath
        } catch (e: Exception) {
            Log.w("PrivetShare", "copyFileToCache failed for $uri", e)
            null
        }
    }

    private fun getFileName(uri: String?): String? {
        if (uri == null) return null
        return try {
            val cursor = contentResolver.query(Uri.parse(uri), null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val idx = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) return it.getString(idx)
                }
            }
            Uri.parse(uri).lastPathSegment
        } catch (_: Exception) {
            Uri.parse(uri).lastPathSegment
        }
    }
}
