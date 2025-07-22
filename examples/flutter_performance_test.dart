// Flutter Performance Test - Examples of performance issues in Flutter apps

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:async';
import 'dart:convert';

class PerformanceIssueApp extends StatefulWidget {
  @override
  _PerformanceIssueAppState createState() => _PerformanceIssueAppState();
}

class _PerformanceIssueAppState extends State<PerformanceIssueApp>
    with TickerProviderStateMixin {
  
  // Performance issue: Controllers not properly disposed
  StreamController<String> _streamController = StreamController<String>();
  AnimationController _animationController;
  Timer _timer;
  StreamSubscription _subscription;
  
  List<String> _items = [];
  List<String> _largeDataSet = List.generate(10000, (index) => 'Item $index');

  @override
  void initState() {
    super.initState();
    
    // Performance issue: Animation controller without dispose
    _animationController = AnimationController(
      duration: Duration(seconds: 2),
      vsync: this,
    );
    
    // Performance issue: Timer without cancel
    _timer = Timer.periodic(Duration(seconds: 1), (timer) {
      setState(() {
        _items.add('New item ${DateTime.now()}');
      });
    });
    
    // Performance issue: Stream subscription without cancel
    _subscription = _streamController.stream.listen((data) {
      setState(() {
        _items.add(data);
      });
    });
    
    // Performance issue: Multiple network calls in loop
    _loadDataInefficiently();
  }

  // Performance issue: Inefficient network calls
  Future<void> _loadDataInefficiently() async {
    for (int i = 0; i < 10; i++) {
      // Performance issue: Sequential network calls
      await http.get(Uri.parse('https://api.example.com/data/$i'));
    }
  }

  // Performance issue: setState with async operations
  void _inefficientAsyncOperation() {
    setState(() {
      // Performance issue: Async operation in setState
      Future.delayed(Duration(seconds: 2), () {
        _items.add('Delayed item');
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Performance Issues Demo'),
      ),
      body: Column(
        children: [
          // Performance issue: Inefficient list rendering
          Expanded(
            child: ListView(
              children: _largeDataSet.map((item) => ListTile(
                title: Text(item),
                subtitle: Text('Subtitle for $item'),
                leading: Icon(Icons.star),
              )).toList(), // Performance issue: .toList() on large dataset
            ),
          ),
          
          // Performance issue: Unoptimized images
          Container(
            height: 200,
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              itemCount: 50,
              itemBuilder: (context, index) {
                return Container(
                  width: 150,
                  margin: EdgeInsets.all(8),
                  child: Column(
                    children: [
                      // Performance issue: Large network images without optimization
                      Image.network(
                        'https://picsum.photos/400/300?random=$index',
                        height: 100,
                        fit: BoxFit.cover,
                      ),
                      // Performance issue: Large file images without optimization
                      Image.asset(
                        'assets/large_image.jpg',
                        height: 80,
                        fit: BoxFit.cover,
                      ),
                    ],
                  ),
                );
              },
            ),
          ),
          
          ElevatedButton(
            onPressed: _inefficientAsyncOperation,
            child: Text('Trigger Inefficient Operation'),
          ),
          
          ElevatedButton(
            onPressed: _inefficientDatabaseOperations,
            child: Text('Inefficient Database Ops'),
          ),
        ],
      ),
    );
  }

  // Performance issue: Inefficient database operations
  Future<void> _inefficientDatabaseOperations() async {
    // Performance issue: Database query in loop
    for (int i = 0; i < 100; i++) {
      // Simulated database query
      await Future.delayed(Duration(milliseconds: 10));
      // database.query('SELECT * FROM table WHERE id = $i');
    }
    
    // Performance issue: Opening database without readonly optimization
    // sqflite.openDatabase('database.db');
  }

  // Performance issue: Build method with expensive operations
  Widget _buildExpensiveWidget() {
    return Container(
      child: Column(
        children: [
          // Performance issue: Expensive operation in build method
          for (int i = 0; i < 1000; i++)
            Container(
              height: 1,
              color: Colors.blue.withOpacity(i / 1000),
            ),
        ],
      ),
    );
  }

  // Performance issue: No dispose method - memory leaks
  // @override
  // void dispose() {
  //   _streamController.close();
  //   _animationController.dispose();
  //   _timer.cancel();
  //   _subscription.cancel();
  //   super.dispose();
  // }
}

// Performance issue: Inefficient widget that rebuilds frequently
class InefficientWidget extends StatefulWidget {
  @override
  _InefficientWidgetState createState() => _InefficientWidgetState();
}

class _InefficientWidgetState extends State<InefficientWidget> {
  int _counter = 0;

  @override
  Widget build(BuildContext context) {
    // Performance issue: Heavy computation in build method
    List<int> heavyComputation = [];
    for (int i = 0; i < 10000; i++) {
      heavyComputation.add(i * i);
    }

    return Column(
      children: [
        Text('Counter: $_counter'),
        // Performance issue: Creating widgets in loop during build
        for (int item in heavyComputation.take(100))
          Container(
            height: 20,
            child: Text('Item: $item'),
          ),
        ElevatedButton(
          onPressed: () {
            setState(() {
              _counter++;
            });
          },
          child: Text('Increment'),
        ),
      ],
    );
  }
}

void main() {
  runApp(MaterialApp(
    home: PerformanceIssueApp(),
  ));
}