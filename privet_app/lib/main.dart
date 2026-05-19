import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'pages/shell_page.dart';

void main() {
  runApp(const ProviderScope(child: PrivetApp()));
}

class PrivetApp extends StatelessWidget {
  const PrivetApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Privet',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const ShellPage(),
    );
  }
}
