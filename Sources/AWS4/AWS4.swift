import CryptoKit
import Foundation

public class AWS4 {
    /// AWS region
    let region: String
    /// AWS access key id
    let accessKeyId: String
    /// AWS secret access key. Used for creating the signature.
    let secretAccessKey: String
    
    /// All supported services. Unsupported services can be used by calling
    /// `.other("ec2")`
    enum Service: CustomStringConvertible {
        case s3
        case es
        case iam
        case other(String)
        
        /// Returns the service as String. Will be used in the signature key.
        var description: String {
            switch self {
            case .s3: return "s3"
            case .es: return "es"
            case .iam: return "iam"
            case .other(let s): return s.lowercased()
            }
        }
    }
    
    /// Initializes the AWS signing algorithm. Uses the provided region, access key and secret access key.
    /// We do **not** recommend to use hardcoded credentials. Use Info.plist in combination of `.xcconfig`
    /// instead.
    init(region: String, accessKeyId: String, secretAccessKey: String) {
        self.accessKeyId = accessKeyId
        self.secretAccessKey = secretAccessKey
        self.region = region
    }
    
    /// Initializes the AWS signing algorithm. Uses the provided region. Access key is retrieved from your Info.plist's
    /// key AWS\_ACCESSKEYID while secret access key is retrieved from AWS\_SECRETACCESSKEY.
    init(region: String) {
        self.accessKeyId = Bundle.main.infoDictionary?["AWS_ACCESSKEYID"] as! String
        self.secretAccessKey = Bundle.main.infoDictionary?["AWS_SECRETACCESSKEY"] as! String
        self.region = region
    }
    
    /// Initializes the AWS signing algorithm. Access key is retrieved from your Info.plist's key
    /// AWS\_ACCESSKEYID, secret access key is retrieved from AWS\_SECRETACCESSKEY, while
    /// region is retrieved from AWS\_REGION.
    init() {
        self.accessKeyId = Bundle.main.infoDictionary?["AWS_ACCESSKEYID"] as! String
        self.secretAccessKey = Bundle.main.infoDictionary?["AWS_SECRETACCESSKEY"] as! String
        self.region = Bundle.main.infoDictionary?["AWS_REGION"] as! String
    }
    
    /// Signs the request for the given service. If another date than the current one has to be used for
    /// the signing, pass it as optional parameter date.
    ///
    /// - Returns: Signed request. Do **not** change any request data after calling this function!
    func sign(request: URLRequest, for service: Service, date: Date = Date()) -> URLRequest {
        var req = request
        
        // 1. add host to headers
        if let h = req.url?.host {
            req.addValue(h, forHTTPHeaderField: "Host")
        }
        
        // 2. add date to headers
        req.addValue(iso8601String(date: date), forHTTPHeaderField: "X-Amz-Date")
        
        // 3. add authorization header
        req.addValue(authHeader(service: service, request: req, date: date), forHTTPHeaderField: "Authorization")
        
        return req
    }
    
    /// Headers that will be part of the canonical request. Headers have to be sorted alphabetically and
    /// in lowercase.
    private var headers: [String] {
        ["Host", "X-Amz-Date", "Content-Type"].map { $0.lowercased() }.sorted { $0 < $1 }
    }
    
    /// Headers that will be signed. Right now all headers will be signed.
    private var signedHeaders: String {
        headers.map { $0.lowercased() }.joined(separator: ";")
    }
    
    /// Generates the Authorization header value. Structure is defined in
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
    ///
    /// - Returns: Authorization header value.
    internal func authHeader(service: Service, request req: URLRequest, date: Date) -> String {
        return [
            "AWS4-HMAC-SHA256",
            "Credential=\(accessKeyId)/\(credentialScope(service: service, date: date)),",
            "SignedHeaders=\(signedHeaders),",
            "Signature=\(signatureOf(request: req, for: service, date: date))"
        ].joined(separator: " ")
    }
    
    /// Generates the string that will be signed. Structure is defined in
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    ///
    /// - Returns: String to sign.
    internal func toSign(service: Service, request req: URLRequest, date: Date) -> String {
        return [
            "AWS4-HMAC-SHA256",
            req.value(forHTTPHeaderField: "X-Amz-Date")!,
            credentialScope(service: service, date: date),
            sha256(string: canonical(request: req, for: service)),
        ].joined(separator: "\n")
    }
    
    /// Generates the signature of a request for a specific service and date.
    ///
    /// - Returns: Signature of the request, service and date.
    internal func signatureOf(request req: URLRequest, for service: Service, date: Date) -> String {
        let k = signatureKey(service: service, date: date).map { String(format: "%02hhx", $0) }.joined()
        print("key: \(k)")
        
        return AWS4.hmac(key: signatureKey(service: service, date: date),
                         data: toSign(service: service, request: req, date: date))
            .map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Generates the canonical path. As explained in
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    /// all path segments have to be url encoded twice (once for S3).
    ///
    /// - Returns: Canonical path.
    private func canonical(path p: String?, for service: Service) -> String {
        guard let p = p else { return "/" }
        
        let paths = p.split(separator: "/")
        var sanitized: [String] = []
        
        for (idx, p) in paths.enumerated() {
            if p == ".." || ((idx + 1) < paths.count && paths[idx+1] == "..") {
                continue
            }
            
            if case .s3 = service {
                sanitized.append(p.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!)
            } else {
                sanitized.append(p.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!
                    .addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!)
            }
        }
        
        if sanitized.count == 0 {
            return "/"
        }
        
        return "/\(sanitized.joined(separator: "/"))/"
    }
    
    /// Generates the canonical request as described in
    /// https://docs.aws.amazon.com/en_us/general/latest/gr/sigv4-create-canonical-request.html
    ///
    /// - Returns: Canonical request
    internal func canonical(request req: URLRequest, for service: Service) -> String {
        var can: [String] = []
        
        // 1. add method
        can.append((req.httpMethod ?? "GET").uppercased())
        
        // 2. add uri
        can.append(canonical(path: req.url?.path, for: service))
        
        // 3. add query string
        if let q = req.url?.query {
            can.append(q)
        } else {
            can.append("")
        }
        
        // 4. add headers
        for header in headers {
            guard let value = req.value(forHTTPHeaderField: header) else { continue }
            can.append("\(header.lowercased()):\(condenseWhitespace(in: value))")
        }
        can.append("")
        
        // 5. add signed headers
        can.append(signedHeaders)
        
        // 6. add payload
        if let b = req.httpBody {
            can.append(sha256(data: b).lowercased())
        } else {
            can.append(sha256(data: Data("".utf8)).lowercased())
        }
        
        return can.joined(separator: "\n")
    }
    
    /// Generates the credential score for a service and date.
    ///
    /// - Returns: Credential scope for a request.
    private func credentialScope(service: Service, date: Date) -> String {
        return "\(dateString(date: date))/\(region)/\(service)/aws4_request"
    }
    
    /// Generates a HMAC encoded string. Key **has** to be passed as Data, as a string representation
    /// will end in an incorrect HMAC chiffre.
    ///
    /// - Returns: HMAC encoded string.
    internal static func hmac(key secret: Data, data: String) -> Data {
        let key = SymmetricKey(data: secret)
        
        let signature = HMAC<SHA256>.authenticationCode(for: Data(data.utf8), using: key)
        return Data(signature)
    }
    
    /// Generates the signature key. As described in
    /// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    /// the key will be created by multiple generation of HMAC strings.
    ///
    /// - Returns: HMAC encoded signature key.
    internal func signatureKey(service: Service, date: Date) -> Data {
        let h1 = AWS4.hmac(key: "AWS4\(secretAccessKey)".data(using: .utf8)!, data: dateString(date: date))
        let h2 = AWS4.hmac(key: h1, data: region)
        let h3 = AWS4.hmac(key: h2, data: service.description)
        
        return AWS4.hmac(key: h3, data: "aws4_request")
    }
    
    /// Reduces multiple spaces to a single one. Code copied from
    /// https://stackoverflow.com/questions/33058676/how-to-remove-multiple-spaces-in-strings-with-swift-2
    ///
    /// - Returns: String without multiple whitespaces.
    private func condenseWhitespace(in s: String) -> String {
        let components = s.components(separatedBy: .whitespacesAndNewlines)
        return components.filter { !$0.isEmpty }.joined(separator: " ")
    }

    /// Generates a SHA256 hash of the given string.
    ///
    /// - Returns: SHA256 hash.
    private func sha256(string: String) -> String {
        return sha256(data: string.data(using: .utf8)!)
    }
    
    /// Generates a SHA256 hash of the given data.
    ///
    /// - Returns: SHA256 hash.
    private func sha256(data: Data) -> String {
        let h = SHA256.hash(data: data)
        return h.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    /// Generates an ISO 8601 date from a date time.
    ///
    /// - Returns: ISO 8601 date: yyyymmdd.
    private func dateString(date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd"
        
        return formatter.string(from: date)
    }
    
    /// Generates an ISO 8601 string from a date time.
    ///
    /// - Returns: ISO 8601 date: yyyymmddThhmmssZ.
    private func iso8601String(date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        
        return formatter.string(from: date)
    }
}
