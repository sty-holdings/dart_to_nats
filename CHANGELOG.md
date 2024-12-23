## 0.2.2
- Fixed message parsing to remove empty lines from headers in `hmsg`

## 0.2.1
- Fixed `pubString` to pass header argument to the `pub` call it wraps
- Fixed `pub` to add an extra `\r\n` to the end of the headers

## 0.2.0
- Added `header` to `pub` and `request` methods in `Client` class

## 0.1.2
- Added request/reply examples in README.md
- Removed `requestJson` from documentation of `request` method in `Client` class

## 0.1.1
- Bumped SDK version to 3.5.4

## 0.1.0
- Forked from [dart-nats](https://github.com/chartchuo/dart-nats).
- Added missing documentation