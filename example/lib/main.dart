import 'package:flutter/material.dart';

void main() {
  runApp(const ExampleApp());
}

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('flutter_sangfor')),
        body: const Center(
          child: Text(
            'aTrust protocol integration is under development.\n'
            'No vendor SDK binaries are bundled.',
            textAlign: TextAlign.center,
          ),
        ),
      ),
    );
  }
}
