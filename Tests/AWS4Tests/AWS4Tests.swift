import XCTest
@testable import AWS4

final class AWS4Tests: XCTestCase {
    ///
    /// Helper function that creates a date from a ISO 8601 string.
    ///
    private func fromISO8601(_ s: String) -> Date {
        let iso = DateFormatter()
        iso.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        
        return iso.date(from: s)!
    }
    
    ///
    /// Checks if the canonical request is generated correctly. Example taken from
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    ///
    func testGetCanonicalRequest() throws {
        let url = URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!
        var req = URLRequest(url: url)
        req.addValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let aws = AWS4(region: "us-east-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        
        let canonical = """
        GET
        /
        Action=ListUsers&Version=2010-05-08
        content-type:application/x-www-form-urlencoded; charset=utf-8
        host:iam.amazonaws.com
        x-amz-date:20150830T123600Z

        content-type;host;x-amz-date
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        
        // Has to be called as it will add missing headers
        let signed = aws.sign(request: req, for: .iam, date: fromISO8601("20150830T123600Z"))
        XCTAssertEqual(aws.canonical(request: signed, for: .iam), canonical)
    }
    
    ///
    /// Checks if the canonical request for a POST request is generated correctly.
    ///
    func testPostCanonicalRequest() throws {
        let url = URL(string: "https://search-test-xxxxxxxxxxxxxxxxxxxxxxxxxx.eu-central-1.es.amazonaws.com/type/index/_search")!
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.httpBody = "{ \"query\": { \"match\": { \"Search\": { \"query\": \"test\", operator: \"and\" } } } }"
            .data(using: .utf8)
        req.addValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let aws = AWS4(region: "eu-central-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        let signed = aws.sign(request: req, for: .es, date: fromISO8601("20200814T173600Z"))
        
        let canonical = """
        POST
        /type/index/_search/
        
        content-type:application/json; charset=utf-8
        host:search-test-xxxxxxxxxxxxxxxxxxxxxxxxxx.eu-central-1.es.amazonaws.com
        x-amz-date:20200814T173600Z

        content-type;host;x-amz-date
        fb969d2de9bd57ffa384c728859418f8f81503e65613e27e0c4381431bcf25f3
        """
        
        XCTAssertEqual(aws.canonical(request: signed, for: .es), canonical)
    }
    
    ///
    /// Checks if the string that will be signed is generated correctly. Example taken from
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    ///
    func testToSign() throws {
        let url = URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!
        var req = URLRequest(url: url)
        req.addValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let date = fromISO8601("20150830T123600Z")
        
        let aws = AWS4(region: "us-east-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        let signed = aws.sign(request: req, for: .iam, date: date)
        
        let toSign = """
        AWS4-HMAC-SHA256
        20150830T123600Z
        20150830/us-east-1/iam/aws4_request
        f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59
        """
        
        XCTAssertEqual(aws.toSign(service: .iam, request: signed, date: date), toSign)
    }
    
    ///
    /// Checks if multiple uses of HMAC still generate the expected results. Reference hashs were generated
    /// by https://github.com/mhart/aws4
    ///
    func testHMAC1() throws {
        let h1 = AWS4.hmac(key: "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".data(using: .utf8)!,
                           data: "20150830")
            .map { String(format: "%02hhx", $0) }.joined()
        
        XCTAssertEqual(h1, "0138c7a6cbd60aa727b2f653a522567439dfb9f3e72b21f9b25941a42f04a7cd")
    }
    
    ///
    /// Checks if multiple uses of HMAC still generate the expected results. Reference hashs were generated
    /// by https://github.com/mhart/aws4
    ///
    func testHMAC2() throws {
        let h1 = AWS4.hmac(key: "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".data(using: .utf8)!,
                           data: "20150830")
        let h2 = AWS4.hmac(key: h1, data: "us-east-1")
            .map { String(format: "%02hhx", $0) }.joined()
        
        XCTAssertEqual(h2, "f33d5808504bf34812e5fade63308b424b244c59189be2a591dd2282c7cb563f")
    }
    
    ///
    /// Checks if multiple uses of HMAC still generate the expected results. Reference hashs were generated
    /// by https://github.com/mhart/aws4
    ///
    func testHMAC3() throws {
        let h1 = AWS4.hmac(key: "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".data(using: .utf8)!,
                           data: "20150830")
        let h2 = AWS4.hmac(key: h1, data: "us-east-1")
        let h3 = AWS4.hmac(key: h2, data: "iam")
            .map { String(format: "%02hhx", $0) }.joined()
        
        XCTAssertEqual(h3, "199e1f48c602a5ae77ce26a46906920e76fc8427aeaa53da643646fcda1ccfb0")
    }
    
    ///
    /// Checks if multiple uses of HMAC still generate the expected results. Reference hashs were generated
    /// by https://github.com/mhart/aws4
    ///
    func testHMAC4() throws {
        let h1 = AWS4.hmac(key: "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".data(using: .utf8)!,
                           data: "20150830")
        let h2 = AWS4.hmac(key: h1, data: "us-east-1")
        let h3 = AWS4.hmac(key: h2, data: "iam")
        let h4 = AWS4.hmac(key: h3, data: "aws4_request")
            .map { String(format: "%02hhx", $0) }.joined()
        
        XCTAssertEqual(h4, "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")
    }
    
    ///
    /// Checks if the  signature key is generated properly. Example taken from
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    ///
    func testSignatureKey() throws {
        let url = URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!
        var req = URLRequest(url: url)
        req.addValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let aws = AWS4(region: "us-east-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        
        let key = aws.signatureKey(service: .iam, date: fromISO8601("20150830T123600Z"))
            .map { String(format: "%02hhx", $0) }.joined()
        
        XCTAssertEqual(key, "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9")
    }
    
    ///
    /// Checks if the signature is generated correctly. Example taken from
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    ///
    func testSignature() throws {
        let url = URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!
        var req = URLRequest(url: url)
        req.addValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let aws = AWS4(region: "us-east-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        let signed = aws.sign(request: req, for: .iam, date: fromISO8601("20150830T123600Z"))
        
        let signature = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        
        XCTAssertEqual(aws.signatureOf(request: signed, for: .iam, date: fromISO8601("20150830T123600Z")), signature)
    }
    
    ///
    /// Checks if the authorization header is generated correctly. Example taken from
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
    ///
    func testIAMAuthorizationHeader() throws {
        let url = URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!
        var req = URLRequest(url: url)
        req.addValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let aws = AWS4(region: "us-east-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        let signed = aws.sign(request: req, for: .iam, date: fromISO8601("20150830T123600Z"))
        
        let header = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        
        XCTAssertEqual(aws.authHeader(service: .iam, request: signed, date: fromISO8601("20150830T123600Z")), header)
    }
    
    ///
    /// Checks if the authorization header is generated properly for POST requests.
    ///
    func testESAuthorizationHeader() throws {
        let url = URL(string: "https://search-test-xxxxxxxxxxxxxxxxxxxxxxxxxx.eu-central-1.es.amazonaws.com")!
        var req = URLRequest(url: url)
        
        req.addValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        req.httpMethod = "POST"
        req.httpBody = "{ \"query\": { \"match\": { \"Search\": { \"query\": \"test\", operator: \"and\" } } } }"
            .data(using: .utf8)
        req.addValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        
        let aws = AWS4(region: "eu-central-1",
                       accessKeyId: "AKIDEXAMPLE",
                       secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
        let signed = aws.sign(request: req, for: .es, date: fromISO8601("20220814T172459Z"))
        
        let header = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20220814/eu-central-1/es/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=a7515571c493e29a32c1f33b6a11d3ba3eccaae1fd173633822188dc4f4c0ac2"
        
        XCTAssertEqual(aws.authHeader(service: .es, request: signed, date: fromISO8601("20220814T172459Z")), header)
    }
}
