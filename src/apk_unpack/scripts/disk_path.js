(function () {
  "use strict";

  var paths = {};
  var found = 0;

  function add(pathValue) {
    if (!pathValue) return;
    var value = String(pathValue).trim();
    if (value.indexOf("/") < 0) return;
    if (paths[value]) return;
    paths[value] = true;
    found += 1;
    APU.emit({ type: "path", path: value });
  }

  function listDexFiles(app, relative) {
    try {
      var File = Java.use("java.io.File");
      var ArrayClass = Java.use("java.lang.reflect.Array");
      var directory = File.$new(app.getFilesDir().getAbsolutePath() + relative);
      if (!directory.exists() || !directory.isDirectory()) return;
      var files = directory.listFiles();
      if (files === null) return;
      var count = ArrayClass.getLength(files);
      for (var i = 0; i < count; i++) {
        var file = Java.cast(ArrayClass.get(files, i), File);
        if (file.isFile() && String(file.getName()).toLowerCase().endsWith(".dex")) {
          add(file.getAbsolutePath());
        }
      }
    } catch (e) {
      APU.emit({ type: "error", where: "list_dex", message: String(e) });
    }
  }

  function enumerateLoaders(app) {
    try {
      var ArrayClass = Java.use("java.lang.reflect.Array");
      var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
      var DexPathList = Java.use("dalvik.system.DexPathList");
      var Element = Java.use("dalvik.system.DexPathList$Element");
      var loaders = [];
      try {
        var enumerated = Java.enumerateClassLoadersSync();
        for (var index = 0; index < enumerated.length; index++) loaders.push(enumerated[index]);
      } catch (e) {}
      try {
        loaders.push(app.getClassLoader());
      } catch (e) {}
      for (var loaderIndex = 0; loaderIndex < loaders.length; loaderIndex++) {
        try {
          var bdcl = Java.cast(loaders[loaderIndex], BaseDexClassLoader);
          var pathListField = BaseDexClassLoader.class.getDeclaredField("pathList");
          pathListField.setAccessible(true);
          var pathList = pathListField.get(bdcl);
          var elementsField = DexPathList.class.getDeclaredField("dexElements");
          elementsField.setAccessible(true);
          var elements = elementsField.get(pathList);
          var count = ArrayClass.getLength(elements);
          for (var i = 0; i < count; i++) {
            try {
              var element = Java.cast(ArrayClass.get(elements, i), Element);
              var dexField = Element.class.getDeclaredField("dexFile");
              dexField.setAccessible(true);
              var dex = dexField.get(element);
              if (dex === null) continue;
              var text = String(dex.toString());
              var match = text.match(/dex file\s+"?([^"]+)"?/);
              if (match) add(match[1]);
              else if (text.indexOf("/") >= 0) add(text);
            } catch (e) {}
          }
        } catch (e) {}
      }
    } catch (e) {
      APU.emit({ type: "error", where: "enumerate_loaders", message: String(e) });
    }
  }

  function start(app) {
    listDexFiles(app, "/prodexdir");
    try {
      listDexFiles(app, "/code_cache");
      APU.emit({ type: "path", path: app.getCodeCacheDir().getAbsolutePath() });
    } catch (e) {}
    enumerateLoaders(app);
    APU.emit({ type: "done", ok: true, count: found, paths: Object.keys(paths) });
  }

  try {
    Java.perform(function () {
      APU.waitForApp(start, Date.now() + (APU.cfg.ready_timeout_ms || 30000));
    });
  } catch (e) {
    APU.emit({ type: "error", where: "bootstrap", message: String(e) });
    APU.emit({ type: "done", ok: false });
  }
})();
