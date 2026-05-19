package com.privet.privet_app

import android.content.UriPermission
import android.net.Uri
import android.provider.OpenableColumns
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream

class MainActivity : FlutterActivity() {
    private val CHANNEL = "privet/file"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
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
                "checkContentUri" -> {
                    val uri = call.argument<String>("uri") ?: return@setMethodCallHandler result.success(false)
                    try {
                        val fd = contentResolver.openFileDescriptor(Uri.parse(uri), "r")
                        fd?.use { result.success(true) } ?: result.success(false)
                    } catch (_: Exception) {
                        result.success(false)
                    }
                }
                else -> result.notImplemented()
            }
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
