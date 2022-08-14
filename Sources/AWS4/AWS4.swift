import CryptoKit
import Foundation

public class AWS4 {
    let region: String
    let service: String
    let accessKeyId: String
    let secretAccessKey: String
    
    init(service: String, region: String, accessKeyId: String, secretAccessKey: String) {
        self.accessKeyId = accessKeyId
        self.secretAccessKey = secretAccessKey
        self.region = region
        self.service = service
    }
    
    init(service: String, region: String) {
        self.accessKeyId = Bundle.main.infoDictionary?["AWS_ACCESSKEYID"] as! String
        self.secretAccessKey = Bundle.main.infoDictionary?["AWS_SECRETACCESSKEY"] as! String
        self.region = region
        self.service = service
    }
    
    init(service: String) {
        self.accessKeyId = Bundle.main.infoDictionary?["AWS_ACCESSKEYID"] as! String
        self.secretAccessKey = Bundle.main.infoDictionary?["AWS_SECRETACCESSKEY"] as! String
        self.region = Bundle.main.infoDictionary?["AWS_REGION"] as! String
        self.service = service
    }
    
    private var headers: [String] {
        ["Host", "X-Amz-Date", "Content-Type"].map { $0.lowercased() }.sorted { $0 < $1 }
    }
    
    private var signedHeaders: String {
        headers.map { $0.lowercased() }.joined(separator: ";")
    }
    
    func sign(request: URLRequest, date: Date = Date()) -> URLRequest {
        var req = request
        
        // 1. add host to headers
        if let h = req.url?.host {
            req.addValue(h, forHTTPHeaderField: "Host")
        }
        
        // 2. add date to headers
        req.addValue(iso8601String(date: date), forHTTPHeaderField: "X-Amz-Date")
        
        // 3. add authorization header
        req.addValue(authHeader(request: req, date: date), forHTTPHeaderField: "Authorization")
        
        return req
    }
    
    internal func authHeader(request req: URLRequest, date: Date) -> String {
        return [
            "AWS4-HMAC-SHA256",
            "Credential=\(accessKeyId)/\(credentialScope(date: date)),",
            "SignedHeaders=\(signedHeaders),",
            "Signature=\(signatureFor(request: req, date: date))"
        ].joined(separator: " ")
    }
    
    internal func toSign(request req: URLRequest, date: Date) -> String {
        return [
            "AWS4-HMAC-SHA256",
            req.value(forHTTPHeaderField: "X-Amz-Date")!,
            credentialScope(date: date),
            sha256(string: canonical(request: req)),
        ].joined(separator: "\n")
    }
    
    internal func signatureFor(request req: URLRequest, date: Date) -> String {
        let k = signatureKey(date: date).map { String(format: "%02hhx", $0) }.joined()
        print("key: \(k)")
        
        return AWS4.hmac(key: signatureKey(date: date),
                         data: toSign(request: req, date: date))
            .map { String(format: "%02hhx", $0) }.joined()
    }
    
    private func canonical(path p: String?) -> String {
        guard let p = p else { return "/" }
        
        let paths = p.split(separator: "/")
        var sanitized: [String] = []
        
        for (idx, p) in paths.enumerated() {
            if p == ".." || ((idx + 1) < paths.count && paths[idx+1] == "..") {
                continue
            }
            
            sanitized.append(p.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!
                .addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)!)
        }
        
        if sanitized.count == 0 {
            return "/"
        }
        
        return "/\(sanitized.joined(separator: "/"))/"
    }
    
    internal func canonical(request req: URLRequest) -> String {
        var can: [String] = []
        // Docs: https://docs.aws.amazon.com/en_us/general/latest/gr/sigv4-create-canonical-request.html
        
        // 1. add method
        can.append((req.httpMethod ?? "GET").uppercased())
        
        // 2. add uri
        can.append(canonical(path: req.url?.path))
        
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
    
    private func credentialScope(date: Date) -> String {
        return "\(dateString(date: date))/\(region)/\(service)/aws4_request"
    }
    
    internal static func hmac(key secret: Data, data: String) -> Data {
        let key = SymmetricKey(data: secret)
        
        let signature = HMAC<SHA256>.authenticationCode(for: Data(data.utf8), using: key)
        return Data(signature)
    }
    
    internal func signatureKey(date: Date) -> Data {
        let h1 = AWS4.hmac(key: "AWS4\(secretAccessKey)".data(using: .utf8)!, data: dateString(date: date))
        let h2 = AWS4.hmac(key: h1, data: region)
        let h3 = AWS4.hmac(key: h2, data: service)
        
        return AWS4.hmac(key: h3, data: "aws4_request")
    }
    
    // source: https://stackoverflow.com/questions/33058676/how-to-remove-multiple-spaces-in-strings-with-swift-2
    private func condenseWhitespace(in s: String) -> String {
        let components = s.components(separatedBy: .whitespacesAndNewlines)
        return components.filter { !$0.isEmpty }.joined(separator: " ")
    }

    private func sha256(string: String) -> String {
        return sha256(data: string.data(using: .utf8)!)
    }
    
    private func sha256(data: Data) -> String {
        let h = SHA256.hash(data: data)
        return h.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    private func dateString(date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd"
        
        return formatter.string(from: date)
    }
    
    private func iso8601String(date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        
        return formatter.string(from: date)
    }
}
