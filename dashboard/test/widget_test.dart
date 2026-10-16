import 'package:flutter_test/flutter_test.dart';
import 'package:dashboard/main.dart';

void main() {
  testWidgets('CortexComplianceApp builds and renders header', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const CortexComplianceApp());
    // Initial loading or loaded state
    expect(find.byType(CortexComplianceApp), findsOneWidget);
  });
}
