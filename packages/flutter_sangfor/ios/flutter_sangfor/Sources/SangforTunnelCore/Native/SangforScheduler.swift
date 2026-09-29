import Foundation

/// A cancellable scheduled action.
public protocol SangforScheduledTask: AnyObject {
  func cancel()
}

/// Time source for the tunnel drivers. Production uses libdispatch; tests use
/// a virtual clock so retransmits and heartbeats are deterministic.
public protocol SangforScheduler: AnyObject {
  /// Runs [action] once after [seconds].
  func schedule(after seconds: Double, _ action: @escaping () -> Void)
    -> SangforScheduledTask

  /// Runs [action] every [seconds] until the task is cancelled.
  func scheduleRepeating(
    every seconds: Double,
    _ action: @escaping () -> Void
  ) -> SangforScheduledTask

  /// Monotonic seconds, for deadlines.
  var now: Double { get }
}

/// libdispatch-backed scheduler used inside the packet tunnel extension.
public final class SangforDispatchScheduler: SangforScheduler {
  private let queue: DispatchQueue

  public init(queue: DispatchQueue) {
    self.queue = queue
  }

  public var now: Double {
    Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000_000
  }

  public func schedule(after seconds: Double, _ action: @escaping () -> Void)
    -> SangforScheduledTask
  {
    let work = DispatchWorkItem(block: action)
    queue.asyncAfter(deadline: .now() + seconds, execute: work)
    return SangforDispatchTask(work)
  }

  public func scheduleRepeating(
    every seconds: Double,
    _ action: @escaping () -> Void
  ) -> SangforScheduledTask {
    let source = DispatchSource.makeTimerSource(queue: queue)
    source.schedule(
      deadline: .now() + seconds,
      repeating: seconds,
      leeway: .milliseconds(50)
    )
    source.setEventHandler(handler: action)
    source.resume()
    return SangforDispatchTimerTask(source)
  }

  private final class SangforDispatchTask: SangforScheduledTask {
    private let work: DispatchWorkItem
    init(_ work: DispatchWorkItem) { self.work = work }
    func cancel() { work.cancel() }
  }

  private final class SangforDispatchTimerTask: SangforScheduledTask {
    private let source: DispatchSourceTimer
    init(_ source: DispatchSourceTimer) { self.source = source }
    func cancel() {
      source.cancel()
    }
  }
}
