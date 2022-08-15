# AWS4

![Badge](https://github.com/s5zy/AWS4/actions/workflows/build.yml/badge.svg)

Basic implementation of AWS Signature Version 4 in Swift for MacOS >= 10.15 and iOS >= 13.

Currently only ElasticSearch (**es**), IAM (**iam**) and some S3 (**s3**) services supported. 
Others may be added in the future. Feel free to open pull requests!

## Installation

```swift
.Package(url: "https://github.com/s5zy/AWS4.git", branch: "main")
```

## Quick Guide

### General

```swift
# Initialize from Info.plist
let aws = AWS4()

# Sign a request
let signed = aws.sign(request: req, for: .iam)
```

#### Credentials

Your credentials will be retrieved from Info.plist if you don't provide them to the
initializer. We recommend to store them in your `.xcconfig` file! Please use

- `AWS_ACCESSKEYID` for your access key
- `AWS_SECRETACCESSKEY` for your secret access key
- `AWS_REGION` for your AWS region

However you can also pass them directly to `AWS4()`, however we do **not** (⚠️) recommend
to hardcode your credentials!

```swift
let aws = AWS4(region: "us-east-1",
               accessKeyId: "AKIDEXAMPLE",
               secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
```

#### Custom date

If you have to use a different datetime than the current one, just pass it to `.sign`:

```swift
let signed = aws.sign(request: req, for: .iam, date: date)
```

### URLRequest

An URLRequest extension that creates the required headers is implemented by us.

**Attention:** Do not change any headers, params, body data, path, ... after calling `signed()`!

```swift
let url = URL(string: "https://search-test-xxxxxxxxxxxxxxxxxxxxxxxxxx.eu-central-1.es.amazonaws.com")!
var req = URLRequest(url: url)
req.addValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")

let (data, _) = try await session.data(for: req.signed(service: .es))
```
