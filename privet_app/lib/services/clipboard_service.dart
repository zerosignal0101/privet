import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:image/image.dart' as img;

/// Clipboard content type returned by [ClipboardService.read].
enum ClipboardContentType { text, image }

/// Result from reading the clipboard.
class ClipboardContent {
  final ClipboardContentType type;
  final String? text;
  final Uint8List? imageBytes;

  const ClipboardContent({required this.type, this.text, this.imageBytes});
}

/// Service for reading clipboard content (text + image on Windows).
class ClipboardService {
  /// Available format constants for reading from clipboard.
  static const String _kTextPlain = 'text/plain';

  /// Read clipboard content — tries text first, then image.
  static Future<ClipboardContent?> read() async {
    // Try text first (all platforms)
    final textData = await Clipboard.getData(_kTextPlain);
    if (textData?.text != null && textData!.text!.trim().isNotEmpty) {
      return ClipboardContent(type: ClipboardContentType.text, text: textData.text);
    }

    // Try image — platform-specific approach
    Uint8List? pngBytes;

    if (Platform.isWindows) {
      // Windows: use Win32 clipboard API directly (CF_DIB → BMP → PNG)
      pngBytes = _readImageFromClipboard();
    } else if (Platform.isAndroid) {
      // Android: use native ClipboardManager via method channel
      try {
        const channel = MethodChannel('privet/file');
        final rawBytes = await channel.invokeMethod<Uint8List>('readClipboardImage');
        if (rawBytes != null && rawBytes.isNotEmpty) {
          final decoded = img.decodeImage(rawBytes);
          pngBytes = decoded != null
              ? Uint8List.fromList(img.encodePng(decoded))
              : rawBytes;
        }
      } catch (_) { }
    }

    if (pngBytes != null) {
      return ClipboardContent(type: ClipboardContentType.image, imageBytes: pngBytes);
    }

    return null;
  }

  /// Return a unique file path under [dir] by appending ` (n)` when the
  /// base name collides with an existing file.  e.g. `"hello.txt"` →
  /// `"hello.txt"` (if absent) or `"hello (1).txt"` (if hello.txt exists).
  static ({String path, String relativePath}) uniqueFile(String dir, String fileName) {
    final file = File('$dir/$fileName');
    if (!file.existsSync()) {
      return (path: file.path, relativePath: fileName);
    }
    final dot = fileName.lastIndexOf('.');
    final stem = dot > 0 ? fileName.substring(0, dot) : fileName;
    final ext = dot > 0 ? fileName.substring(dot) : '';
    for (int i = 1; i <= 999; i++) {
      final candidate = '$stem ($i)$ext';
      if (!File('$dir/$candidate').existsSync()) {
        return (path: '$dir/$candidate', relativePath: candidate);
      }
    }
    return (path: file.path, relativePath: fileName); // fallback, overwrites
  }

  /// Save clipboard content to a file under [dir].
  /// Returns absolute path, relative path, and file size; null on failure.
  static Future<({String absolutePath, String relativePath, int size})?> saveToFile(
    String dir,
  ) async {
    final content = await read();
    if (content == null) return null;

    switch (content.type) {
      case ClipboardContentType.text:
        final text = content.text!;
        final name = textFilename(text);
        final (path: filePath, relativePath: relPath) = uniqueFile(dir, '$name.txt');
        final file = File(filePath);
        await file.writeAsString(text);
        final size = await file.length();
        return (absolutePath: file.path, relativePath: relPath, size: size);

      case ClipboardContentType.image:
        final ts = DateTime.now().millisecondsSinceEpoch;
        final (path: filePath, relativePath: relPath) = uniqueFile(dir, 'clipboard_$ts.png');
        final file = File(filePath);
        await file.writeAsBytes(content.imageBytes!);
        final size = await file.length();
        return (absolutePath: file.path, relativePath: relPath, size: size);
    }
  }

  /// Derive a filename from the first ~24 usable characters of [text].
  static String textFilename(String text) {
    final cleaned = text.replaceAll(RegExp(r'[\s\n\r]+'), '_').replaceAll(RegExp(r'[^\w\-_.()]'), '');
    if (cleaned.length <= 24) return cleaned.isEmpty ? 'clipboard' : cleaned;
    return cleaned.substring(0, 24);
  }

  /// On Windows only: read file paths from the clipboard (e.g. files copied
  /// via Explorer via Ctrl+C).  Returns `null` on non-Windows or when no
  /// file paths are present.
  static List<String>? readFilePaths() {
    if (!Platform.isWindows) return null;
    return _readFileListFromClipboard();
  }
}

// ---------------------------------------------------------------------------
// Win32 clipboard FFI (Windows-only, for reading image data)
// ---------------------------------------------------------------------------

final DynamicLibrary _user32 = DynamicLibrary.open('user32.dll');
final DynamicLibrary _kernel32 = DynamicLibrary.open('kernel32.dll');

final int Function(Pointer<Void>) _openClipboard = _user32
    .lookupFunction<Int32 Function(Pointer<Void>), int Function(Pointer<Void>)>('OpenClipboard');
final int Function() _closeClipboard = _user32
    .lookupFunction<Int32 Function(), int Function()>('CloseClipboard');
final Pointer<Void> Function(int) _getClipboardData = _user32
    .lookupFunction<Pointer<Void> Function(Uint32), Pointer<Void> Function(int)>('GetClipboardData');
final int Function(int) _isFormatAvailable = _user32
    .lookupFunction<Int32 Function(Uint32), int Function(int)>('IsClipboardFormatAvailable');
final Pointer<Void> Function(Pointer<Void>) _globalLock = _kernel32
    .lookupFunction<Pointer<Void> Function(Pointer<Void>), Pointer<Void> Function(Pointer<Void>)>('GlobalLock');
final int Function(Pointer<Void>) _globalUnlock = _kernel32
    .lookupFunction<Int32 Function(Pointer<Void>), int Function(Pointer<Void>)>('GlobalUnlock');
final int Function(Pointer<Void>) _globalSize = _kernel32
    .lookupFunction<IntPtr Function(Pointer<Void>), int Function(Pointer<Void>)>('GlobalSize');

const int _cfDib = 8;
const int _cfHDrop = 15; // CF_HDROP — file list from Explorer copy

/// On Windows: read file paths from CF_HDROP clipboard format.
/// Returns null if no file paths are available.
List<String>? _readFileListFromClipboard() {
  if (_openClipboard(nullptr) == 0) return null;

  try {
    if (_isFormatAvailable(_cfHDrop) == 0) return null;

    final handle = _getClipboardData(_cfHDrop);
    if (handle == nullptr) return null;

    final locked = _globalLock(handle);
    if (locked == nullptr) return null;

    try {
      final size = _globalSize(handle);
      if (size < 20) return null; // at least DROPFILES header

      final raw = locked.cast<Uint8>().asTypedList(size);

      // DROPFILES layout (all offsets from start of struct):
      //   0: pFiles  (Uint32) — offset to file list
      //   4: pt      (POINT, 8 bytes)
      //  12: fNC     (Int32)
      //  16: fWide   (Int32) — non-zero = UTF-16 file names
      final buf = raw.buffer;
      final pFiles = ByteData.view(buf, 0, 4).getUint32(0, Endian.little);
      final fWide = ByteData.view(buf, 16, 4).getUint32(0, Endian.little);

      if (pFiles < 20 || pFiles >= size) return null;

      final paths = <String>[];
      int off = pFiles;
      if (fWide != 0) {
        // UTF-16LE null-terminated strings, double-null terminated
        while (off + 2 <= size) {
          // Read UTF-16 code units until null terminator
          final codeUnits = <int>[];
          while (off + 2 <= size) {
            final cu = raw[off] | (raw[off + 1] << 8);
            off += 2;
            if (cu == 0) break; // null terminator
            codeUnits.add(cu);
          }
          if (codeUnits.isEmpty) break; // double null = end of list
          paths.add(String.fromCharCodes(codeUnits));
        }
      } else {
        // ANSI (single-byte) null-terminated strings
        while (off < size) {
          final bytes = <int>[];
          while (off < size && raw[off] != 0) {
            bytes.add(raw[off]);
            off++;
          }
          off++; // skip null
          if (bytes.isEmpty) break;
          paths.add(String.fromCharCodes(bytes));
        }
      }

      return paths.isNotEmpty ? paths : null;
    } finally {
      _globalUnlock(handle);
    }
  } finally {
    _closeClipboard();
  }
}

/// Read image data from the Windows clipboard (CF_DIB → BMP → PNG).
Uint8List? _readImageFromClipboard() {
  if (_openClipboard(nullptr) == 0) return null;

  try {
    if (_isFormatAvailable(_cfDib) == 0) return null;

    final handle = _getClipboardData(_cfDib);
    if (handle == nullptr) return null;

    final locked = _globalLock(handle);
    if (locked == nullptr) return null;

    try {
      final size = _globalSize(handle);
      if (size <= 0) return null;

      final dib = locked.cast<Uint8>().asTypedList(size);

      // Prepend a BMP file header so the image decoder can read it.
      final bmp = _dibToBmp(dib);
      if (bmp == null) return null;

      final image = img.decodeImage(bmp);
      if (image == null) return null;

      return Uint8List.fromList(img.encodePng(image));
    } finally {
      _globalUnlock(handle);
    }
  } finally {
    _closeClipboard();
  }
}

/// Convert a DIB (Device Independent Bitmap) byte array to a full BMP by
/// prepending the BMP file header. Returns null if the DIB header is invalid.
Uint8List? _dibToBmp(Uint8List dib) {
  if (dib.length < 40) return null;

  try {
    final h = ByteData.sublistView(dib);
    final biSize = h.getUint32(0, Endian.little);

    if (biSize < 12 || biSize > dib.length) return null;

    final bitCount = biSize >= 16 ? h.getUint16(14, Endian.little) : 0;
    int colorTableSize = 0;
    if (bitCount <= 8) {
      final clrUsed = biSize >= 36 ? h.getUint32(32, Endian.little) : 0;
      colorTableSize = (clrUsed != 0 ? clrUsed : 1 << (bitCount < 1 ? 1 : bitCount)) * 4;
    }

    final pixelOffset = 14 + biSize + colorTableSize;
    final pixelDataSize = dib.length - biSize - colorTableSize;
    if (pixelDataSize < 0) return null;

    final bmp = Uint8List(pixelOffset + pixelDataSize);

    // BMP file header (14 bytes)
    final fh = ByteData.sublistView(bmp, 0, 14);
    fh.setUint16(0, 0x4D42, Endian.little); // 'BM'
    fh.setUint32(2, bmp.length, Endian.little); // total file size
    fh.setUint16(6, 0, Endian.little); // reserved
    fh.setUint16(8, 0, Endian.little); // reserved
    fh.setUint32(10, pixelOffset, Endian.little); // pixel data offset

    // Copy DIB header + palette
    bmp.setRange(14, 14 + biSize + colorTableSize, dib, 0);

    // Copy pixel data
    bmp.setRange(pixelOffset, pixelOffset + pixelDataSize, dib, biSize + colorTableSize);

    return bmp;
  } catch (_) {
    return null;
  }
}
