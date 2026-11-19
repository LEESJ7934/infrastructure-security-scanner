"""Bounded scheduling and explicit untested observations on interruption/deadline."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import math
import time


def validate_execution(timeout, max_workers=1):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("timeout must be finite and in (0,30]")
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 1000:
        raise ValueError("max_workers must be in 1..1000")


def bounded_scan(ports, worker, *, max_workers, protocol, stop_event=None, deadline=None):
    """Only max_workers jobs outstanding; completed results survive cancellation.

    An in-flight operation is allowed to finish within its socket timeout. No
    packet is sent for queued ports after cancellation. Missing ports are explicit.
    """
    results, pending, submitted = [], {}, set()
    iterator = iter(ports)
    stopped = None
    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                stopped = "cancelled"
            if deadline is not None and time.monotonic() >= deadline:
                stopped = "deadline_exceeded"
            while not stopped and len(pending) < max_workers:
                port = next(iterator, None)
                if port is None:
                    break
                pending[executor.submit(worker, port)] = port
                submitted.add(port)
            if not pending:
                break
            completed, _ = wait(pending, timeout=.05, return_when=FIRST_COMPLETED)
            for future in completed:
                port = pending.pop(future)
                try:
                    results.append(future.result().to_dict())
                except Exception:
                    results.append({"port": port, "protocol": protocol, "state": "error",
                                    "reason": "worker_error", "error_code": "WORKER_ERROR"})
    except KeyboardInterrupt:
        stopped = "interrupted"
        if stop_event is not None:
            stop_event.set()
    finally:
        # Completed in-flight observations remain evidence, even after Ctrl+C.
        for future, port in pending.items():
            if future.cancel():
                submitted.discard(port)
                continue
            try:
                results.append(future.result().to_dict())
            except Exception:
                results.append({"port": port, "protocol": protocol, "state": "error",
                                "reason": "worker_error", "error_code": "WORKER_ERROR"})
        executor.shutdown(wait=True, cancel_futures=True)
    observed = {row["port"] for row in results}
    results.extend({"port": port, "protocol": protocol, "state": "not_tested",
                    "reason": stopped or "not_executed", "error_code": None}
                   for port in ports if port not in observed)
    return sorted(results, key=lambda row: row["port"])
