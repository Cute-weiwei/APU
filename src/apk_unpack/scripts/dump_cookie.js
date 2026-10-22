(function () {
  "use strict";

  var saved = 0;
  var candidates = 0;
  var outDir = null;

  function dumpCookieValue(value, label, meta) {
    if (!value) return false;
    meta = meta || {};
    var base = ptr(value);
    // Android 8 uses +0x10/+0x18; Android 9 x86_64 uses +0x08/+0x10 in the
    // cases documented in the knowledge base. Probe both and accept only an
    // address whose first four bytes are the DEX magic.
    // Probe several ART DexFile layouts: Android 8/9 x86_64 use
    // +0x08/+0x10 or +0x10/+0x18; newer/other builds have been observed
    // at +0x00/+0x08 and +0x18/+0x20. Only an address whose first bytes are
    // the DEX magic and whose size is plausible is accepted.
    // Layout fields use the target process pointer width, not the device ABI.
    var width = Process.pointerSize;
    var probes = [[1, 2], [2, 3], [0, 1], [3, 4], [4, 5]].map(function (pair) {
      return [pair[0] * width, pair[1] * width];
    });
    for (var index = 0; index < probes.length; index++) {
      var begin;
      var size;
      try {
        begin = base.add(probes[index][0]).readPointer();
        var sizeField = base.add(probes[index][1]);
        var rawSize = width === 4 ? sizeField.readU32() : sizeField.readU64();
        size = parseInt(rawSize.toString(), 10);
      } catch (e) {
        continue;
      }
      if (!begin || begin.isNull()) continue;
      if (!(size >= 112 && size <= 512 * 1024 * 1024)) continue;
      if (!APU.dexMagicOk(begin)) continue;
      var path = outDir + "/loader" + meta.loader + "_" + label + "_" + begin.toString() + "_" + size + ".dex";
      if (APU.writeBytes(begin, size, path)) {
        saved += 1;
        APU.emit({
          type: "saved",
          path: path,
          size: size,
          label: label,
          offset: probes[index][0],
          loader: meta.loader,
          loader_id: meta.loader_id,
          loader_path: meta.loader_path,
          element_path: meta.element_path,
          dex_path: meta.dex_path,
          target_loader: meta.target_loader,
        });
        return true;
      }
      return false;
    }
    APU.emit({ type: "error", where: "cookie", label: label, message: "no DEX magic at probed offsets" });
    return false;
  }

  function start(app) {
    outDir = APU.ensureDir(app, "");
    if (!outDir) {
      APU.emit({ type: "done", ok: false, saved: 0, candidates: 0 });
      return;
    }
    APU.emit({ type: "ready", out_dir: outDir });
    APU.emit({ type: "progress", stage: "reflection_setup" });

    var ArrayClass = Java.use("java.lang.reflect.Array");
    var DexFileClass = Java.use("dalvik.system.DexFile");
    var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    var DexPathList = Java.use("dalvik.system.DexPathList");
    var Element = Java.use("dalvik.system.DexPathList$Element");

    var loaders = [];
    var loaderKeys = [];
    var seenLoaders = {};
    var targetLoaderKey = null;

    function addLoader(loader) {
      if (loader === null) return null;
      var key;
      try {
        key = loader.toString();
      } catch (e) {
        key = String(loader);
      }
      if (seenLoaders[key]) return key;
      seenLoaders[key] = true;
      loaders.push(loader);
      loaderKeys.push(key);
      APU.emit({ type: "loader", index: loaders.length - 1, id: key });
      return key;
    }

    if (APU.cfg.activity_class) {
      try {
        targetLoaderKey = addLoader(Java.use(APU.cfg.activity_class).class.getClassLoader());
      } catch (e) {
        // Activity may not be loaded yet; classloader enumeration still works.
      }
    }
    try {
      var appLoaderKey = addLoader(app.getClassLoader());
      if (targetLoaderKey === null) targetLoaderKey = appLoaderKey;
    } catch (e) {}
    try {
      var enumerated = Java.enumerateClassLoadersSync();
      for (var loaderIndex = 0; loaderIndex < enumerated.length; loaderIndex++) {
        addLoader(enumerated[loaderIndex]);
      }
    } catch (e) {
      APU.emit({ type: "error", where: "enumerate_loaders", message: String(e) });
    }

    APU.emit({ type: "progress", stage: "loaders", count: loaders.length, target_loader: targetLoaderKey });

    // DexPathList$Element hides the backing file in a private field on some
    // Android versions; record it when readable so plugin/non-target DEX can
    // be labelled in the evidence instead of being counted as target output.
    function elementPath(element) {
      var names = ["path", "file", "zip"];
      for (var n = 0; n < names.length; n++) {
        try {
          var field = Element.class.getDeclaredField(names[n]);
          field.setAccessible(true);
          var value = field.get(element);
          if (value !== null) return String(value);
        } catch (e) {}
      }
      return null;
    }

    function dexPath(dexFile) {
      var names = ["mFileName", "mPath"];
      for (var n = 0; n < names.length; n++) {
        try {
          var field = DexFileClass.class.getDeclaredField(names[n]);
          field.setAccessible(true);
          var value = field.get(dexFile);
          if (value !== null) return String(value);
        } catch (e) {}
      }
      return null;
    }

    for (var loaderIndex = 0; loaderIndex < loaders.length; loaderIndex++) {
      var loader = loaders[loaderIndex];
      var bdcl;
      try {
        bdcl = Java.cast(loader, BaseDexClassLoader);
      } catch (e) {
        continue;
      }
      var elements;
      try {
        var pathListField = BaseDexClassLoader.class.getDeclaredField("pathList");
        pathListField.setAccessible(true);
        var pathList = pathListField.get(bdcl);
        var elementsField = DexPathList.class.getDeclaredField("dexElements");
        elementsField.setAccessible(true);
        elements = elementsField.get(pathList);
      } catch (e) {
        continue;
      }
      var length = 0;
      try {
        length = ArrayClass.getLength(elements);
      } catch (e) {}
      APU.emit({ type: "progress", stage: "loader_elements", loader: loaderIndex, elements: length });
      for (var i = 0; i < length; i++) {
        var dex = null;
        try {
          var element = Java.cast(ArrayClass.get(elements, i), Element);
          var dexField = Element.class.getDeclaredField("dexFile");
          dexField.setAccessible(true);
          dex = dexField.get(element);
        } catch (e) {
          continue;
        }
        if (dex === null) continue;
        var dexFile;
        try {
          dexFile = Java.cast(dex, DexFileClass);
        } catch (e) {
          continue;
        }
        var cookie = null;
        try {
          var cookieField = DexFileClass.class.getDeclaredField("mCookie");
          cookieField.setAccessible(true);
          cookie = cookieField.get(dexFile);
        } catch (e) {}
        if (cookie === null) continue;
        var cookieLength = 0;
        try {
          cookieLength = ArrayClass.getLength(cookie);
        } catch (e) {}
        var loaderKey = loaderKeys[loaderIndex] || String(loaderIndex);
        var meta = {
          loader: loaderIndex,
          loader_id: loaderKey,
          loader_path: elementPath(element),
          element_path: elementPath(element),
          dex_path: dexPath(dexFile),
          target_loader: loaderKey === targetLoaderKey,
        };
        APU.emit({
          type: "candidate",
          loader: loaderIndex,
          loader_id: loaderKey,
          target_loader: meta.target_loader,
          element_path: meta.element_path,
          dex_path: meta.dex_path,
          elem: i,
          cookie_len: cookieLength,
        });
        if (cookieLength <= 0) continue;
        if (cookieLength === 1) {
          var single = 0;
          try {
            single = ArrayClass.getLong(cookie, 0);
          } catch (e) {}
          if (single > 0x10000) {
            candidates += 1;
            dumpCookieValue(single, "elem" + i + "_cookie0", meta);
          }
        } else {
          for (var j = 1; j < cookieLength; j++) {
            var value = 0;
            try {
              value = ArrayClass.getLong(cookie, j);
            } catch (e) {
              continue;
            }
            if (value <= 0x10000) continue;
            candidates += 1;
            dumpCookieValue(value, "elem" + i + "_cookie" + j, meta);
          }
        }
      }
    }
    APU.emit({ type: "done", ok: true, candidates: candidates, saved: saved });
  }

  function bootstrap() {
    Java.perform(function () {
      APU.waitForApp(start, Date.now() + (APU.cfg.ready_timeout_ms || 30000));
    });
  }

  try {
    bootstrap();
  } catch (e) {
    APU.emit({ type: "error", where: "bootstrap", message: String(e) });
    APU.emit({ type: "done", ok: false, saved: saved, candidates: candidates });
  }
})();
