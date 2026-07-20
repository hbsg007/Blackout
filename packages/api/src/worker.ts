// Separate entrypoint so the queue worker runs as its own process/container.
import { startWorker } from "./lib/queue.js";
startWorker();
