import 'dart:io';

import 'package:flutter/material.dart';

import '../models/file_tree.dart';

/// A reusable file tree widget that shows FileTreeNode recursively.
/// Used in send preparation (with remove buttons) and history (read-only).
class FileTreeView extends StatelessWidget {
  final List<FileTreeNode> nodes;
  final void Function(String relativePath)? onRemoveFile;
  final void Function(String fullPath)? onOpenFile;
  final bool showRemoveButtons;
  final String Function(int bytes)? formatSize;

  const FileTreeView({
    super.key,
    this.nodes = const [],
    this.onRemoveFile,
    this.onOpenFile,
    this.showRemoveButtons = false,
    this.formatSize,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: _buildNodeList(context, nodes, 0),
    );
  }

  List<Widget> _buildNodeList(
    BuildContext context,
    List<FileTreeNode> nodes,
    int depth,
  ) {
    final widgets = <Widget>[];
    for (final node in nodes) {
      widgets.add(_buildNode(context, node, depth));
    }
    return widgets;
  }

  Widget _buildNode(BuildContext context, FileTreeNode node, int depth) {
    if (node.isDir) {
      return _DirectoryNode(
        node: node,
        depth: depth,
        showRemoveButtons: showRemoveButtons,
        onRemoveFile: onRemoveFile,
        onOpenFile: onOpenFile,
        formatSize: formatSize,
      );
    }
    final exists = node.fullPath != null && File(node.fullPath!).existsSync();
    return _FileNode(
      node: node,
      depth: depth,
      showRemoveButton: showRemoveButtons,
      onRemove: onRemoveFile != null
          ? () => onRemoveFile!(node.relativePath)
          : null,
      onOpen: onOpenFile != null && node.fullPath != null && exists
          ? () => onOpenFile!(node.fullPath!)
          : null,
      fileExists: exists,
      formatSize: formatSize,
    );
  }
}

class _DirectoryNode extends StatefulWidget {
  final FileTreeNode node;
  final int depth;
  final bool showRemoveButtons;
  final void Function(String relativePath)? onRemoveFile;
  final void Function(String fullPath)? onOpenFile;
  final String Function(int bytes)? formatSize;

  const _DirectoryNode({
    required this.node,
    required this.depth,
    required this.showRemoveButtons,
    this.onRemoveFile,
    this.onOpenFile,
    this.formatSize,
  });

  @override
  State<_DirectoryNode> createState() => _DirectoryNodeState();
}

class _DirectoryNodeState extends State<_DirectoryNode> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final sizeText = widget.formatSize != null
        ? widget.formatSize!(widget.node.totalSize)
        : _formatSize(widget.node.totalSize);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: EdgeInsets.only(left: 16.0 * widget.depth),
          child: ListTile(
            dense: true,
            leading: Icon(
              _expanded ? Icons.folder_open : Icons.folder,
              size: 20,
              color: Colors.amber.shade600,
            ),
            title: Text(
              widget.node.name,
              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500),
              overflow: TextOverflow.ellipsis,
            ),
            subtitle: Text(
              '${widget.node.fileCount} files, $sizeText',
              style: TextStyle(fontSize: 11, color: Colors.grey.shade600),
            ),
            trailing: widget.showRemoveButtons && widget.onRemoveFile != null
                ? IconButton(
                    icon: const Icon(Icons.close, size: 16),
                    onPressed: () => widget.onRemoveFile!(widget.node.relativePath),
                    tooltip: 'Remove folder',
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  )
                : IconButton(
                    icon: Icon(
                      _expanded ? Icons.expand_less : Icons.expand_more,
                      size: 18,
                    ),
                    onPressed: () => setState(() => _expanded = !_expanded),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
            onTap: () => setState(() => _expanded = !_expanded),
          ),
        ),
        if (_expanded)
          ..._buildChildren(context, widget.node.children, widget.depth + 1),
      ],
    );
  }

  List<Widget> _buildChildren(
    BuildContext context,
    List<FileTreeNode> children,
    int depth,
  ) {
    final widgets = <Widget>[];
    for (final child in children) {
      if (child.isDir) {
        widgets.add(_DirectoryNode(
          node: child,
          depth: depth,
          showRemoveButtons: widget.showRemoveButtons,
          onRemoveFile: widget.onRemoveFile,
          onOpenFile: widget.onOpenFile,
          formatSize: widget.formatSize,
        ));
      } else {
        final exists = child.fullPath != null && File(child.fullPath!).existsSync();
        widgets.add(_FileNode(
          node: child,
          depth: depth,
          showRemoveButton: widget.showRemoveButtons,
          onRemove: widget.onRemoveFile != null
              ? () => widget.onRemoveFile!(child.relativePath)
              : null,
          onOpen: widget.onOpenFile != null && child.fullPath != null && exists
              ? () => widget.onOpenFile!(child.fullPath!)
              : null,
          fileExists: exists,
          formatSize: widget.formatSize,
        ));
      }
    }
    return widgets;
  }
}

class _FileNode extends StatelessWidget {
  final FileTreeNode node;
  final int depth;
  final bool showRemoveButton;
  final VoidCallback? onRemove;
  final VoidCallback? onOpen;
  final bool fileExists;
  final String Function(int bytes)? formatSize;

  const _FileNode({
    required this.node,
    required this.depth,
    this.showRemoveButton = false,
    this.onRemove,
    this.onOpen,
    this.fileExists = false,
    this.formatSize,
  });

  @override
  Widget build(BuildContext context) {
    final sizeText = formatSize != null
        ? formatSize!(node.size)
        : _formatSize(node.size);

    return Padding(
      padding: EdgeInsets.only(left: 16.0 * depth),
      child: ListTile(
        dense: true,
        leading: Icon(
          fileExists ? Icons.insert_drive_file : Icons.file_present,
          size: 18,
          color: fileExists ? null : Colors.grey,
        ),
        title: Text(
          node.name,
          style: TextStyle(
            fontSize: 13,
            color: fileExists ? null : Colors.grey,
          ),
          overflow: TextOverflow.ellipsis,
        ),
        subtitle: Text(
          fileExists ? sizeText : 'File not accessible',
          style: TextStyle(
            fontSize: 11,
            color: fileExists ? Colors.grey.shade600 : Colors.orange,
          ),
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (onOpen != null)
              IconButton(
                icon: const Icon(Icons.open_in_new, size: 16),
                tooltip: 'Open file',
                onPressed: onOpen,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
            if (showRemoveButton && onRemove != null)
              IconButton(
                icon: const Icon(Icons.close, size: 16),
                onPressed: onRemove,
                tooltip: 'Remove file',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
          ],
        ),
      ),
    );
  }
}

String _formatSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
}
