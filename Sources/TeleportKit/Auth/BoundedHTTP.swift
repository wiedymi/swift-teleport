import Foundation
import Security
import TeleportCore

/// One request owns its session. The serial delegate bounds bytes before appending them.
final class BoundedHTTP: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let proxy: TeleportProxy
    private let limit: Int
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, any Error>?
    private var session: URLSession?
    private var body = Data()
    private var status = 0
    private var stopped = false

    init(proxy: TeleportProxy, limit: Int = 1_048_576) { self.proxy = proxy; self.limit = limit }

    func run(path: String, query: [URLQueryItem] = [], body: Data? = nil, method: String? = nil,
             timeout: TimeInterval = 60) async throws -> Data {
        guard timeout.isFinite, timeout > 0, timeout <= 180 else { throw TeleportError.invalidConfiguration("HTTP timeout") }
        var endpoint = URLComponents(url: proxy.url.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        if !query.isEmpty { endpoint.queryItems = query }
        var request = URLRequest(url: endpoint.url!)
        request.httpMethod = method ?? (body == nil ? "GET" : "POST")
        request.httpBody = body
        request.timeoutInterval = timeout
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                lock.lock()
                if stopped { lock.unlock(); continuation.resume(throwing: CancellationError()); return }
                self.continuation = continuation
                let configuration = URLSessionConfiguration.ephemeral
                configuration.urlCache = nil; configuration.httpCookieStorage = nil; configuration.httpShouldSetCookies = false
                configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
                configuration.timeoutIntervalForResource = timeout
                let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
                let session = URLSession(configuration: configuration, delegate: self, delegateQueue: queue)
                self.session = session
                let task = session.dataTask(with: request)
                lock.unlock(); task.resume()
            }
        } onCancel: { self.finish(.failure(CancellationError())) }
    }

    private func finish(_ result: Result<Data, any Error>) {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        stopped = true
        let c = continuation; continuation = nil
        let s = session; session = nil
        body.removeAll(keepingCapacity: false)
        lock.unlock()
        s?.invalidateAndCancel(); c?.resume(with: result)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else { completionHandler(.cancel); finish(.failure(TeleportError.invalidResponse("HTTP response"))); return }
        guard response.expectedContentLength <= Int64(limit) else { completionHandler(.cancel); finish(.failure(TeleportError.limitExceeded("HTTP body"))); return }
        lock.lock(); status = http.statusCode; lock.unlock()
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        guard data.count <= limit - body.count else { lock.unlock(); finish(.failure(TeleportError.limitExceeded("HTTP body"))); return }
        body.append(data); lock.unlock()
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        if let error { finish(.failure(error)); return }
        lock.lock(); let data = body; let code = status; lock.unlock()
        finish(code == 200 ? .success(data) : .failure(TeleportError.httpStatus(code)))
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              !proxy.httpsCACertificatesDER.isEmpty else { completionHandler(.performDefaultHandling, nil); return }
        guard challenge.protectionSpace.host.lowercased() == proxy.url.host?.lowercased(), let trust = challenge.protectionSpace.serverTrust else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        let certificates = proxy.httpsCACertificatesDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certificates.count == proxy.httpsCACertificatesDER.count,
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, proxy.url.host! as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, certificates as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil) else { completionHandler(.cancelAuthenticationChallenge, nil); return }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
