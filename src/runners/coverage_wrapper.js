import { Readable, Writable } from 'node:stream';
import inspector from 'node:inspector';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (process.argv.length < 3) {
  console.error("Usage: node coverage_wrapper.js <target_script> [args...]");
  process.exit(1);
}

const targetScript = path.resolve(process.argv[2]);
const targetArgs = process.argv.slice(3);

// Set process.argv so the target script gets its expected arguments
process.argv = [process.argv[0], targetScript, ...targetArgs];

// Setup V8 Inspector session
const session = new inspector.Session();
session.connect();

// Enable Profiler and start precise coverage once at startup
session.post('Profiler.enable');
session.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });

// Track and profile Node.js Worker threads dynamically
const workerSessions = new Map();
session.on('NodeWorker.attachedToWorker', (event) => {
  const info = event.params || event;
  const workerSession = new inspector.Session();
  try {
    workerSession.connect(info.sessionId);
    workerSession.post('Profiler.enable');
    workerSession.post('Profiler.startPreciseCoverage', { callCount: true, detailed: true });
    workerSessions.set(info.sessionId, workerSession);
  } catch (e) {}
});

session.on('NodeWorker.detachedFromWorker', (event) => {
  const info = event.params || event;
  workerSessions.delete(info.sessionId);
});

session.post('NodeWorker.enable', { waitForDebuggerOnStart: false });

// Intercept stdin and stdout
const realStdin = process.stdin;
const realStdout = process.stdout;

// Custom streams that the target script will think are the standard ones
const customStdin = new Readable({
  read() {}
});

const customStdout = new Writable({
  write(chunk, encoding, callback) {
    handleTargetStdout(chunk);
    callback();
  }
});

Object.defineProperty(process, 'stdin', { value: customStdin, writable: true, configurable: true });
Object.defineProperty(process, 'stdout', { value: customStdout, writable: true, configurable: true });

import net from 'node:net';

const socketPath = process.env.FUZZER_SOCKET_PATH || '/tmp/mcp_fuzzer.sock';

const socketServer = net.createServer((socket) => {
  let socketBuffer = '';

  socket.on('data', (chunk) => {
    socketBuffer += chunk.toString();
    let lineEnd;
    while ((lineEnd = socketBuffer.indexOf('\n')) !== -1) {
      const line = socketBuffer.slice(0, lineEnd).trim();
      socketBuffer = socketBuffer.slice(lineEnd + 1);
      if (line) {
        handleSocketMessage(socket, line);
      }
    }
  });
});

try {
  if (fs.existsSync(socketPath)) {
    fs.unlinkSync(socketPath);
  }
} catch (e) {}

socketServer.listen(socketPath, () => {
  realStdout.write(`SOCKET_READY:${socketPath}\n`);
});

function handleSocketMessage(socket, line) {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'tools/call') {
      activeSocket = socket;
      isFuzzingCall = true;
    }
  } catch (e) {}
  // Forward to target script stdin
  customStdin.push(line + '\n');
}

let activeSocket = null;
let isFuzzingCall = false;

function handleTargetStdout(chunk) {
  const dataStr = chunk.toString();
  if (isFuzzingCall && activeSocket) {
    const targetSocket = activeSocket;
    isFuzzingCall = false;
    
    // Take precise coverage without stopping it
    session.post('Profiler.takePreciseCoverage', (err, covRes) => {
      const combinedResults = [];
      if (!err && covRes && covRes.result) {
        combinedResults.push(...covRes.result);
      }

      const coverageReport = processCoverage(combinedResults);
      const payload = JSON.stringify({
        response: dataStr.trim(),
        coverage: coverageReport
      }) + '\n';

      targetSocket.write(payload);
    });
  } else {
    realStdout.write(chunk);
  }
}

// Line offset caching logic
const fileLineOffsets = new Map();

function getLineOffsets(filePath) {
  if (fileLineOffsets.has(filePath)) {
    return fileLineOffsets.get(filePath);
  }
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const offsets = [0];
    for (let i = 0; i < content.length; i++) {
      if (content[i] === '\n') {
        offsets.push(i + 1);
      }
    }
    fileLineOffsets.set(filePath, offsets);
    return offsets;
  } catch (e) {
    return null;
  }
}

function offsetToLine(offsets, offset) {
  let low = 0;
  let high = offsets.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if (offsets[mid] <= offset) {
      if (mid === offsets.length - 1 || offsets[mid + 1] > offset) {
        return mid + 1; // 1-based line number
      }
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return 1;
}

// Find package root (directory containing package.json or the parent of build/src)
let targetDir = path.dirname(targetScript);
while (targetDir !== path.parse(targetDir).root) {
  if (fs.existsSync(path.join(targetDir, 'package.json'))) {
    break;
  }
  targetDir = path.dirname(targetDir);
}

const localFileCache = new Map();

function isLocalFile(fileUrl) {
  if (!fileUrl.startsWith('file://')) return false;
  if (localFileCache.has(fileUrl)) return localFileCache.get(fileUrl);
  const filePath = fileURLToPath(fileUrl);
  const matched = filePath.startsWith(targetDir) && !filePath.includes('node_modules') && !filePath.includes('.venv');
  localFileCache.set(fileUrl, matched);
  return matched;
}

// PER-CALL coverage. V8 ALREADY gives us this -- do not delta it again.
//
// MEASURED 2026-09-10 with a standalone inspector.Session: running the same
// 1000-iteration loop before three consecutive takePreciseCoverage calls gives
//     take #1: nonzero=8 maxCount=1000
//     take #2: nonzero=8 maxCount=1000
//     take #3: nonzero=8 maxCount=1000
// Counts do NOT accumulate -- takePreciseCoverage RESETS the execution
// counters. range.count is therefore already "executed by THIS call".
//
// An earlier fix assumed the opposite (nazmul.todo item 10 flagged that
// assumption as unverified, and it was wrong). It kept a prevCounts map and
// reported a range only when count > prevCount, which after the first call
// suppressed nearly everything: cov: 1388 stayed identical from execution #13
// to #8192 while corp: held at 1/32b, on twelve semantically distinct seeds.
// Reverted to reporting every executed range.
//
// WHAT V8 BLOCK COVERAGE ACTUALLY REPORTS, AND WHY count>0 THREW IT AWAY.
//
// MEASURED 2026-09-10 on one function with three branches, detailed:true:
//   [routes  ] isBlockCoverage=true ranges= 157-265:1  207-263:0
//   [services] isBlockCoverage=true ranges= 157-265:1  194-207:0  244-263:0
//   [zzz     ] isBlockCoverage=true ranges= 157-265:1  194-207:0  231-244:0
//
// V8 emits ONE range covering the whole function with its execution count, then
// carves out the branches that did NOT run as nested count:0 sub-ranges. So the
// set of count>0 ranges is IDENTICAL for all three inputs (just 157-265) and
// every bit of branch information lives in the count:0 ranges the old filter
// discarded. Three inputs taking three different branches produced one
// identical coverage set, which is why libFuzzer's cov: never moved:
//   before: cov: 1388 ft: 1388 corp: 1/32b, unchanged #13 -> #8192
//
// Correct semantics: a region executed iff it is inside a count>0 range and NOT
// inside a nested count:0 range. executedIntervals() does that subtraction and
// returns disjoint executed intervals, keyed by byte offset.
//
// Byte offsets, not line numbers. The previous code expanded every range to
// whole lines and unioned them, which re-merges branches that share a line --
// and most Set A targets ship a minified/transpiled dist/index.js where an
// entire handler is one line.
function executedIntervals(ranges) {
  // V8 ranges within a function are properly nested; outermost first.
  const sorted = [...ranges].sort(
    (a, b) => a.startOffset - b.startOffset || b.endOffset - a.endOffset);
  const out = [];
  for (let i = 0; i < sorted.length; i++) {
    const r = sorted[i];
    if (r.count <= 0) continue;            // not executed; its own children are moot
    // Subtract this range's IMMEDIATE children. A child with count>0 emits its
    // own intervals when it is reached as `r`, so subtracting it here is right
    // either way; what matters is that a count:0 child leaves a hole.
    let cursor = r.startOffset;
    for (let j = i + 1; j < sorted.length; j++) {
      const c = sorted[j];
      if (c.startOffset >= r.endOffset) break;   // past the end of r
      if (c.endOffset > r.endOffset) continue;   // overlaps out of r, not nested
      if (c.startOffset < cursor) continue;      // nested inside an earlier child
      if (c.startOffset > cursor) out.push([cursor, c.startOffset]);
      cursor = c.endOffset;
    }
    if (cursor < r.endOffset) out.push([cursor, r.endOffset]);
  }
  return out;
}

function processCoverage(result) {
  const covered = [];

  for (const script of result) {
    if (!isLocalFile(script.url)) continue;
    const fileName = path.basename(fileURLToPath(script.url));

    for (const func of script.functions) {
      for (const [a, b] of executedIntervals(func.ranges)) {
        covered.push(`${fileName}|${a}|${b}`);
      }
    }
  }
  return [...new Set(covered)];
}

// Dynamically import the target script (supports both ESM and CommonJS via dynamic import)
import(pathToFileURL(targetScript).href).catch((err) => {
  console.error("Failed to load target script:", err);
  process.exit(1);
});
