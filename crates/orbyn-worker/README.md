# orbyn-worker

The job runner. Each job kind has one handler; an unknown kind retries with backoff and then fails, so no work is dropped silently. `zone_changed` is the hook for silent push and does nothing until push providers exist.
