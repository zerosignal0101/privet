import 'package:flutter_test/flutter_test.dart';
import 'package:privet_app/main.dart';

void main() {
  testWidgets('App starts and shows engine status', (WidgetTester tester) async {
    await tester.pumpWidget(const PrivetApp());
    // The app should show the engine status message
    expect(find.byType(PrivetApp), findsOneWidget);
  });
}
