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

// Read from the real stdin (fuzzer inputs)
let inputBuffer = '';
realStdin.on('data', (chunk) => {
  inputBuffer += chunk.toString();
  let lineEnd;
  while ((lineEnd = inputBuffer.indexOf('\n')) !== -1) {
    const line = inputBuffer.slice(0, lineEnd).trim();
    inputBuffer = inputBuffer.slice(lineEnd + 1);
    if (line) {
      handleFuzzerInput(line);
    }
  }
});

let isFuzzingCall = false;

function handleFuzzerInput(line) {
  try {
    const msg = JSON.parse(line);
    if (msg.method === 'tools/call') {
      isFuzzingCall = true;
    }
  } catch (e) {
    // Not a valid JSON or not a tool call
  }
  // Forward to target script stdin
  customStdin.push(line + '\n');
}

function handleTargetStdout(chunk) {
  const dataStr = chunk.toString();
  if (isFuzzingCall) {
    isFuzzingCall = false;
    
    // Take precise coverage without stopping it
    session.post('Profiler.takePreciseCoverage', (err, covRes) => {
      // Output the response to real stdout first
      realStdout.write(chunk);
      
      // Process and output coverage metadata line
      if (!err && covRes && covRes.result) {
        const coverageReport = processCoverage(covRes.result);
        realStdout.write('COV: ' + JSON.stringify(coverageReport) + '\n');
      } else {
        realStdout.write('COV: []\n');
      }
    });
  } else {
    // Just forward it (e.g. initialization logs, standard MCP messages)
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

const targetDir = path.dirname(targetScript);

function isLocalFile(fileUrl) {
  if (!fileUrl.startsWith('file://')) return false;
  const filePath = fileURLToPath(fileUrl);
  return filePath.startsWith(targetDir) && !filePath.includes('node_modules');
}

function processCoverage(result) {
  const coveredLines = [];
  
  for (const script of result) {
    if (!isLocalFile(script.url)) continue;
    const filePath = fileURLToPath(script.url);
    const fileName = path.basename(filePath);
    const lineOffsets = getLineOffsets(filePath);
    if (!lineOffsets) continue;
    
    for (const func of script.functions) {
      for (const range of func.ranges) {
        if (range.count > 0) {
          const startLine = offsetToLine(lineOffsets, range.startOffset);
          const endLine = offsetToLine(lineOffsets, range.endOffset);
          for (let line = startLine; line <= endLine; line++) {
            coveredLines.push(`${fileName}:${line}`);
          }
        }
      }
    }
  }
  return [...new Set(coveredLines)];
}

// Dynamically import the target script (supports both ESM and CommonJS via dynamic import)
import(pathToFileURL(targetScript).href).catch((err) => {
  console.error("Failed to load target script:", err);
  process.exit(1);
});
