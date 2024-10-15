const inject = require('../index');

inject.inject("inject.exe", 'foobar', Buffer.from("Hello, fib-inject!"));
