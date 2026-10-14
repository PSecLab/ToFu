const fs = require('fs');
const path = require('path');
const util = require('util');

const DEFAULT_LOG_PATH = path.join(__dirname, '..', '..', 'results', 'oracle.json');
const LOG_DIR = process.env.MCP_FUZZER_ORACLE_LOG || DEFAULT_LOG_PATH;

const logDir = path.dirname(LOG_DIR);
try {
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
} catch (e) {
  process.stderr.write(`[HOOK WARNING] Failed to create log directory ${logDir}, using /tmp\n`);
}

const originalFsAppendFileSync = fs.appendFileSync;
const originalFsWriteFileSync = fs.writeFileSync;
const originalFsAppendFile = fs.appendFile;
const originalFsWriteFile = fs.writeFile;

function getStackTrace() {
  const stack = new Error().stack;
  if (!stack) return [];
  const lines = stack.split('\n').slice(3); // Skip Error, getStackTrace, log
  return lines.slice(0, 20).map(line => line.trim()).filter(Boolean);
}

function extractOriginFromStack(stack) {
  if (!Array.isArray(stack)) return null;
  for (const frame of stack) {
    if (typeof frame !== 'string') continue;
    if (frame.includes('node_hook.js')) continue;
    if (frame.includes('node:internal')) continue;
    if (frame.includes('/node_modules/')) continue;
    const fnMatch = frame.match(/\bat\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|$)/);
    let locMatch = frame.match(/\((.*?):(\d+):(\d+)\)$/);
    if (!locMatch) {
      locMatch = frame.match(/\bat\s+(.*?):(\d+):(\d+)$/);
    }
    if (!locMatch) continue;
    return {
      function: fnMatch ? fnMatch[1] : '',
      file: locMatch[1],
      line: Number(locMatch[2]),
      column: Number(locMatch[3]),
      frame,
    };
  }
  return null;
}

function captureContext() {
  const stack = getStackTrace();
  return {
    stack,
    origin: extractOriginFromStack(stack),
  };
}

function filterEnvVars(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const filtered = {};
  const envKeys = ['env', 'ENV', 'environment', 'processEnv'];
  for (const key in obj) {
    if (envKeys.includes(key) && typeof obj[key] === 'object') {
      filtered[key] = '[Environment variables filtered]';
    } else if (key === 'options' && obj[key] && typeof obj[key] === 'object') {
      const opts = { ...obj[key] };
      if (opts.env) {
        opts.env = '[Environment variables filtered]';
      }
      filtered[key] = opts;
    } else {
      filtered[key] = obj[key];
    }
  }
  return filtered;
}

function log(sink, ...args) {
  const timestamp = new Date().toISOString();
  let context = null;
  if (
    args.length > 0 &&
    args[args.length - 1] &&
    typeof args[args.length - 1] === 'object' &&
    args[args.length - 1].__mcp_fuzzer_context === true
  ) {
    context = args.pop();
  }
  const captured = context || captureContext();
  const stack = captured.stack || [];

  const entry = {
    timestamp,
    sink,
    args: args.map(arg => {
      if (typeof arg === 'string') {
        return arg;
      } else if (Buffer.isBuffer(arg)) {
        return `[Buffer:${arg.length} bytes]`;
      } else if (arg && typeof arg === 'object') {
        try {
          const filtered = filterEnvVars(arg);
          return JSON.stringify(filtered);
        } catch (e) {
          return `[Object:${Object.keys(arg).join(',')}]`;
        }
      }
      return String(arg);
    }),
    stack,
  };
  if (captured.origin) {
    entry.origin = captured.origin;
  }

  const line = JSON.stringify(entry) + '\n';

  try {
    originalFsAppendFileSync.call(fs, LOG_DIR, line, 'utf8');
  } catch (e) {
    process.stderr.write(`[HOOK ERROR] Failed to write log: ${e.message}\n`);
    process.stderr.write(line);
  }
}

const cp = require('child_process');

const origExec = cp.exec;
cp.exec = function (command, options, callback) {
  const cmd = String(command);
  const callContext = { __mcp_fuzzer_context: true, ...captureContext() };
  let optsCopy = null;
  if (options && typeof options === 'object') {
    try {
      optsCopy = JSON.parse(JSON.stringify(options));
    } catch (e) {
      optsCopy = options;
    }
  } else {
    optsCopy = options;
  }

  setImmediate(() => {
    try {
      log('child_process.exec', cmd, optsCopy, callContext);
    } catch (e) {
    }
  });

  const originalCallback = callback;

  const wrappedCallback = originalCallback && typeof originalCallback === 'function'
    ? function(error, stdout, stderr) {
        const stdoutStr = stdout ? (Buffer.isBuffer(stdout) ? stdout.toString('utf8') : String(stdout)) : '';
        const stderrStr = stderr ? (Buffer.isBuffer(stderr) ? stderr.toString('utf8') : String(stderr)) : '';

        setImmediate(() => {
          try {
            log('child_process.exec.result', {
              command: cmd,
              error: error ? error.message : null,
              code: error ? error.code : null,
              stdout: stdoutStr.substring(0, 10000),
              stderr: stderrStr.substring(0, 10000),
              stdoutLength: stdoutStr.length,
              stderrLength: stderrStr.length,
            }, callContext);
          } catch (e) {
          }
        });

        return originalCallback.call(this, error, stdout, stderr);
      }
    : null;

  const childProcess = wrappedCallback
    ? origExec.call(this, command, options, wrappedCallback)
    : origExec.apply(this, arguments);

  childProcess.on('error', (error) => {
    setImmediate(() => {
      try {
        log('child_process.exec.error', {
          command: cmd,
          error: error.message,
          code: error.code,
        }, callContext);
      } catch (e) {
      }
    });
  });

  return childProcess;
};

if (origExec && origExec[util.promisify.custom]) {
  cp.exec[util.promisify.custom] = function(command, options) {
    return new Promise((resolve, reject) => {
      cp.exec.call(this, command, options, (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout;
          err.stderr = stderr;
          reject(err);
          return;
        }
        resolve({ stdout, stderr });
      });
    });
  };
}

const origExecSync = cp.execSync;
cp.execSync = function (command, options) {
  const cmd = String(command);
  const callContext = { __mcp_fuzzer_context: true, ...captureContext() };
  let optsCopy = null;
  if (options && typeof options === 'object') {
    try {
      optsCopy = JSON.parse(JSON.stringify(options));
    } catch (e) {
      optsCopy = options;
    }
  } else {
    optsCopy = options;
  }

  setImmediate(() => {
    try {
      log('child_process.execSync', cmd, optsCopy, callContext);
    } catch (e) {
    }
  });

  return origExecSync.apply(this, arguments);
};

const origSpawn = cp.spawn;
cp.spawn = function (command, args, options) {
  const cmd = String(command);
  const callContext = { __mcp_fuzzer_context: true, ...captureContext() };
  const argsCopy = args ? (Array.isArray(args) ? [...args] : args) : args;
  let optsCopy = null;
  if (options && typeof options === 'object') {
    try {
      optsCopy = JSON.parse(JSON.stringify(options));
    } catch (e) {
      optsCopy = options;
    }
  } else {
    optsCopy = options;
  }

  setImmediate(() => {
    try {
      log('child_process.spawn', cmd, argsCopy, optsCopy, callContext);
    } catch (e) {
    }
  });

  return origSpawn.apply(this, arguments);
};

const origSpawnSync = cp.spawnSync;
cp.spawnSync = function (command, args, options) {
  const cmd = String(command);
  const callContext = { __mcp_fuzzer_context: true, ...captureContext() };
  const argsCopy = args ? (Array.isArray(args) ? [...args] : args) : args;
  let optsCopy = null;
  if (options && typeof options === 'object') {
    try {
      optsCopy = JSON.parse(JSON.stringify(options));
    } catch (e) {
      optsCopy = options;
    }
  } else {
    optsCopy = options;
  }

  setImmediate(() => {
    try {
      log('child_process.spawnSync', cmd, argsCopy, optsCopy, callContext);
    } catch (e) {
    }
  });

  return origSpawnSync.apply(this, arguments);
};

const origExecFile = cp.execFile;
cp.execFile = function (file, args, options, callback) {
  const fileStr = String(file);
  const callContext = { __mcp_fuzzer_context: true, ...captureContext() };
  const argsCopy = args ? (Array.isArray(args) ? [...args] : args) : args;
  let optsCopy = null;
  if (options && typeof options === 'object') {
    try {
      optsCopy = JSON.parse(JSON.stringify(options));
    } catch (e) {
      optsCopy = options;
    }
  } else {
    optsCopy = options;
  }

  setImmediate(() => {
    try {
      log('child_process.execFile', fileStr, argsCopy, optsCopy, callContext);
    } catch (e) {
    }
  });

  return origExecFile.apply(this, arguments);
};

const origExecFileSync = cp.execFileSync;
cp.execFileSync = function (file, args, options) {
  const fileStr = String(file);
  const callContext = { __mcp_fuzzer_context: true, ...captureContext() };
  const argsCopy = args ? (Array.isArray(args) ? [...args] : args) : args;
  let optsCopy = null;
  if (options && typeof options === 'object') {
    try {
      optsCopy = JSON.parse(JSON.stringify(options));
    } catch (e) {
      optsCopy = options;
    }
  } else {
    optsCopy = options;
  }

  setImmediate(() => {
    try {
      log('child_process.execFileSync', fileStr, argsCopy, optsCopy, callContext);
    } catch (e) {
    }
  });

  return origExecFileSync.apply(this, arguments);
};

const fsModule = require('fs');

const origWriteFile = fsModule.writeFile;
fsModule.writeFile = function (file, data, options, callback) {
  const filePath = typeof file === 'string' ? file : file.toString();
  if (filePath !== LOG_DIR) {
    log('fs.writeFile', filePath, typeof data === 'string' ? data.substring(0, 200) : `[${typeof data}]`);
  }
  return origWriteFile.apply(this, arguments);
};

const origWriteFileSync = fsModule.writeFileSync;
fsModule.writeFileSync = function (file, data, options) {
  const filePath = typeof file === 'string' ? file : file.toString();
  if (filePath !== LOG_DIR) {
    log('fs.writeFileSync', filePath, typeof data === 'string' ? data.substring(0, 200) : `[${typeof data}]`);
  }
  return origWriteFileSync.apply(this, arguments);
};

const origAppendFile = fsModule.appendFile;
fsModule.appendFile = function (file, data, options, callback) {
  const filePath = typeof file === 'string' ? file : file.toString();
  if (filePath !== LOG_DIR) {
    log('fs.appendFile', filePath, typeof data === 'string' ? data.substring(0, 200) : `[${typeof data}]`);
  }
  return origAppendFile.apply(this, arguments);
};

fsModule.appendFileSync = function (file, data, options) {
  const filePath = typeof file === 'string' ? file : file.toString();
  if (filePath !== LOG_DIR) {
    log('fs.appendFileSync', filePath, typeof data === 'string' ? data.substring(0, 200) : `[${typeof data}]`);
  }
  return originalFsAppendFileSync.apply(this, arguments);
};

const origUnlink = fsModule.unlink;
fsModule.unlink = function (targetPath, callback) {
  log('fs.unlink', targetPath);
  return origUnlink.apply(this, arguments);
};

const origUnlinkSync = fsModule.unlinkSync;
fsModule.unlinkSync = function (targetPath) {
  log('fs.unlinkSync', targetPath);
  return origUnlinkSync.apply(this, arguments);
};

const origRmdir = fsModule.rmdir;
if (origRmdir) {
  fsModule.rmdir = function (targetPath, options, callback) {
    log('fs.rmdir', targetPath, options);
    return origRmdir.apply(this, arguments);
  };
}

const origRmdirSync = fsModule.rmdirSync;
if (origRmdirSync) {
  fsModule.rmdirSync = function (targetPath, options) {
    log('fs.rmdirSync', targetPath, options);
    return origRmdirSync.apply(this, arguments);
  };
}

const origRm = fsModule.rm;
if (origRm) {
  fsModule.rm = function (targetPath, options, callback) {
    log('fs.rm', targetPath, options);
    return origRm.apply(this, arguments);
  };
}

const origRmSync = fsModule.rmSync;
if (origRmSync) {
  fsModule.rmSync = function (targetPath, options) {
    log('fs.rmSync', targetPath, options);
    return origRmSync.apply(this, arguments);
  };
}

const http = require('http');
const https = require('https');

const origHttpRequest = http.request;
http.request = function (url, options, callback) {
  const target = typeof url === 'string'
    ? url
    : (options && options.host ? `${options.protocol || 'http:'}//${options.host}${options.path || '/'}` : 'unknown');
  log('http.request', target, options);
  return origHttpRequest.apply(this, arguments);
};

const origHttpGet = http.get;
http.get = function (url, options, callback) {
  const target = typeof url === 'string'
    ? url
    : (options && options.host ? `${options.protocol || 'http:'}//${options.host}${options.path || '/'}` : 'unknown');
  log('http.get', target, options);
  return origHttpGet.apply(this, arguments);
};

const origHttpsRequest = https.request;
https.request = function (url, options, callback) {
  const target = typeof url === 'string'
    ? url
    : (options && options.host ? `${options.protocol || 'https:'}//${options.host}${options.path || '/'}` : 'unknown');
  log('https.request', target, options);
  return origHttpsRequest.apply(this, arguments);
};

const origHttpsGet = https.get;
https.get = function (url, options, callback) {
  const target = typeof url === 'string'
    ? url
    : (options && options.host ? `${options.protocol || 'https:'}//${options.host}${options.path || '/'}` : 'unknown');
  log('https.get', target, options);
  return origHttpsGet.apply(this, arguments);
};

const vm = require('vm');

const origRunInContext = vm.runInContext;
vm.runInContext = function (code, context, options) {
  const codeStr = typeof code === 'string' ? code : code.toString();
  log('vm.runInContext', codeStr.substring(0, 500), options);
  return origRunInContext.apply(this, arguments);
};

const origRunInNewContext = vm.runInNewContext;
vm.runInNewContext = function (code, context, options) {
  const codeStr = typeof code === 'string' ? code : code.toString();
  log('vm.runInNewContext', codeStr.substring(0, 500), options);
  return origRunInNewContext.apply(this, arguments);
};

const origRunInThisContext = vm.runInThisContext;
vm.runInThisContext = function (code, options) {
  const codeStr = typeof code === 'string' ? code : code.toString();
  log('vm.runInThisContext', codeStr.substring(0, 500), options);
  return origRunInThisContext.apply(this, arguments);
};

log('hook_init', {
  nodeVersion: process.version,
  pid: process.pid,
  cwd: process.cwd(),
  logFile: LOG_DIR,
});
// PATCH (ToFu): sidecar "<oracle log>.hook_init" marker. The engine truncates the oracle
// log between rounds (_clear_oracle), which erases this hook_init line, so a run with no
// sink hit looked identical to a run whose hook never loaded. The sidecar is never cleared.
try {
  originalFsAppendFileSync(LOG_DIR + '.hook_init',
    JSON.stringify({ timestamp: new Date().toISOString(), pid: process.pid, node: process.version }) + '\n');
} catch (e) { /* marker is best-effort; never break the target */ }
