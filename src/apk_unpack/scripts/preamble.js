(function () {
  "use strict";

  var cfg = globalThis.APU_CONFIG || {};
  var outDir = null;

  function emit(obj) {
    try {
      console.log("APU::" + JSON.stringify(obj));
    } catch (e) {
      // The host ignores non-marker output.
    }
  }

  function getApp() {
    try {
      var ActivityThread = Java.use("android.app.ActivityThread");
      var current = ActivityThread.currentActivityThread();
      if (current !== null) {
        var application = current.getApplication();
        if (application !== null) return application;
      }
    } catch (e) {
      // The VM/Application may not be ready yet.
    }
    return null;
  }

  function waitForApp(callback, deadline) {
    var app = getApp();
    if (app !== null) {
      try {
        callback(app);
      } catch (e) {
        emit({ type: "error", where: "callback", message: String(e) });
        emit({ type: "done", ok: false });
      }
      return;
    }
    if (Date.now() > deadline) {
      emit({ type: "error", where: "app", message: "application not ready before deadline" });
      emit({ type: "done", ok: false });
      return;
    }
    setTimeout(function () {
      waitForApp(callback, deadline);
    }, 100);
  }

  function ensureDir(app, suffix) {
    try {
      var File = Java.use("java.io.File");
      var base = File.$new(app.getFilesDir().getAbsolutePath() + "/apu/" + (cfg.run_id || "run"));
      if (!base.exists()) base.mkdirs();
      var target = base;
      if (suffix) {
        target = File.$new(base.getAbsolutePath() + "/" + suffix);
        if (!target.exists()) target.mkdirs();
      }
      outDir = target.getAbsolutePath();
      return outDir;
    } catch (e) {
      emit({ type: "error", where: "mkdir", message: String(e) });
      return null;
    }
  }

  function installAntiKill() {
    if (!cfg.anti_kill) return;
    try {
      var libc = Process.getModuleByName("libc.so");
      function replace(name, signature, ret) {
        try {
          var address = libc.getExportByName(name);
          Interceptor.replace(
            address,
            new NativeCallback(function () {
              return ret;
            }, signature[0], signature[1])
          );
          emit({ type: "anti_kill", hook: name });
        } catch (e) {
          // Some symbols are absent or inlined on this build.
        }
      }
      replace("exit", ["void", ["int"]], undefined);
      replace("_exit", ["void", ["int"]], undefined);
      replace("abort", ["void", ["int"]], undefined);
      replace("quick_exit", ["void", ["int"]], undefined);
      replace("kill", ["int", ["int", "int"]], 0);
      replace("tgkill", ["int", ["int", "int", "int"]], 0);
      replace("raise", ["int", ["int"]], 0);
    } catch (e) {
      emit({ type: "error", where: "anti_kill", message: String(e) });
    }
  }

  var nativeApi = null;

  function getNative() {
    if (nativeApi) return nativeApi;
    var libc = Process.getModuleByName("libc.so");
    var sizeType = Process.pointerSize === 4 ? "uint" : "uint64";
    nativeApi = {
      fopen: new NativeFunction(libc.getExportByName("fopen"), "pointer", ["pointer", "pointer"]),
      fwrite: new NativeFunction(libc.getExportByName("fwrite"), sizeType, [
        "pointer",
        sizeType,
        sizeType,
        "pointer",
      ]),
      fclose: new NativeFunction(libc.getExportByName("fclose"), "int", ["pointer"]),
    };
    return nativeApi;
  }

  function writeBytes(base, size, path) {
    try {
      var api = getNative();
      var file = api.fopen(Memory.allocUtf8String(path), Memory.allocUtf8String("wb"));
      if (file.isNull()) {
        emit({ type: "error", where: "fopen", path: path });
        return false;
      }
      var written = api.fwrite(base, 1, size, file);
      api.fclose(file);
      var ok = String(written) === String(size) || written.toString() === String(size);
      if (!ok) {
        emit({ type: "error", where: "fwrite", path: path, written: String(written), size: String(size) });
      }
      return ok;
    } catch (e) {
      emit({ type: "error", where: "write", path: path, message: String(e) });
      return false;
    }
  }

  function readU8(pointer) {
    try {
      return pointer.readU8();
    } catch (e) {
      return -1;
    }
  }

  function dexMagicOk(pointer) {
    return (
      readU8(pointer) === 0x64 &&
      readU8(pointer.add(1)) === 0x65 &&
      readU8(pointer.add(2)) === 0x78 &&
      readU8(pointer.add(3)) === 0x0a
    );
  }

  function hardStop() {
    setTimeout(function () {
      emit({ type: "error", where: "hard_timeout", message: "script hard timeout" });
      emit({ type: "done", ok: false, saved: 0, candidates: 0 });
    }, cfg.hard_timeout_ms || 170000);
  }

  globalThis.APU = {
    cfg: cfg,
    emit: emit,
    getApp: getApp,
    waitForApp: waitForApp,
    ensureDir: ensureDir,
    installAntiKill: installAntiKill,
    writeBytes: writeBytes,
    dexMagicOk: dexMagicOk,
    hardStop: hardStop,
  };

  emit({ type: "hello", pid: Process.id, frida: Frida.version });
  installAntiKill();
  hardStop();
})();
