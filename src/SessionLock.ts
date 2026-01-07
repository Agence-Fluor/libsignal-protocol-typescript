/**
 * Session lock manager - serializes operations on sessions
 * to prevent race conditions in async operations.
 */

const jobQueue: Map<string, Promise<unknown>> = new Map();

/**
 * Queue a job for a specific identifier (address).
 * Jobs for the same identifier run sequentially.
 */
export function queueJobForNumber<T>(
  number: string,
  runJob: () => Promise<T>
): Promise<T> {
  const runPrevious = jobQueue.get(number) ?? Promise.resolve();
  
  const runCurrent = runPrevious.then(runJob, runJob);
  jobQueue.set(number, runCurrent);
  
  // Clean up when done
  void runCurrent.then(() => {
    if (jobQueue.get(number) === runCurrent) {
      jobQueue.delete(number);
    }
  });
  
  return runCurrent as Promise<T>;
}

