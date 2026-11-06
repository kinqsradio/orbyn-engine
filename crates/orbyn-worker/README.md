# orbyn-worker

The job runner. Each job kind has one handler; an unknown kind retries with backoff and then fails, so no work is dropped silently.
