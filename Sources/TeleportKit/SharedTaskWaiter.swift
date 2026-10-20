import Foundation

/// A canceled caller releases its continuation without canceling a shared task.
final class SharedTaskWaiter<Value: Sendable>: @unchecked Sendable {
    private enum State {
        case pending(CheckedContinuation<Value, any Error>?)
        case completed(Result<Value, any Error>)
    }
    private let lock = NSLock()
    private var state: State = .pending(nil)

    private func finish(_ result: Result<Value, any Error>) {
        lock.lock()
        guard case .pending(let continuation) = state else { lock.unlock(); return }
        state = .completed(result)
        lock.unlock()
        continuation?.resume(with: result)
    }

    private func install(_ continuation: CheckedContinuation<Value, any Error>) {
        lock.lock()
        switch state {
        case .pending:
            state = .pending(continuation)
            lock.unlock()
        case .completed(let result):
            lock.unlock()
            continuation.resume(with: result)
        }
    }

    static func wait(for task: Task<Value, any Error>) async throws -> Value {
        let waiter = SharedTaskWaiter<Value>()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                waiter.install(continuation)
                Task { waiter.finish(await task.result) }
            }
        } onCancel: { waiter.finish(.failure(CancellationError())) }
    }
}
