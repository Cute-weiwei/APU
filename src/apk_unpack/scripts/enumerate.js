(function () {
  "use strict";

  var outDir = null;
  var total = 0;

  function start(app) {
    outDir = APU.ensureDir(app, "classes");
    if (!outDir) {
      APU.emit({ type: "done", ok: false });
      return;
    }
    var ArrayClass = Java.use("java.lang.reflect.Array");
    var DexFileClass = Java.use("dalvik.system.DexFile");
    var BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
    var DexPathList = Java.use("dalvik.system.DexPathList");
    var Element = Java.use("dalvik.system.DexPathList$Element");
    var Collections = Java.use("java.util.Collections");
    var FileWriter = Java.use("java.io.FileWriter");
    var BufferedWriter = Java.use("java.io.BufferedWriter");

    var loaders = [];
    try {
      var enumerated = Java.enumerateClassLoadersSync();
      for (var index = 0; index < enumerated.length; index++) loaders.push(enumerated[index]);
    } catch (e) {}
    try {
      loaders.push(app.getClassLoader());
    } catch (e) {}

    for (var loaderIndex = 0; loaderIndex < loaders.length; loaderIndex++) {
      var elements;
      try {
        var bdcl = Java.cast(loaders[loaderIndex], BaseDexClassLoader);
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
      for (var i = 0; i < length; i++) {
        var dex;
        try {
          var element = Java.cast(ArrayClass.get(elements, i), Element);
          var dexField = Element.class.getDeclaredField("dexFile");
          dexField.setAccessible(true);
          dex = dexField.get(element);
        } catch (e) {
          continue;
        }
        if (dex === null) continue;
        var path = outDir + "/loader" + loaderIndex + "_elem" + i + ".txt";
        var writer = null;
        try {
          writer = BufferedWriter.$new(FileWriter.$new(path));
          var dexFile = Java.cast(dex, DexFileClass);
          var enumeration = dexFile.entries();
          var list = Collections.list(enumeration);
          var count = list.size();
          for (var j = 0; j < count; j++) {
            writer.write(String(list.get(j)));
            writer.newLine();
            total += 1;
          }
          APU.emit({ type: "saved", path: path, count: count, kind: "class-list" });
        } catch (e) {
          APU.emit({ type: "error", where: "entries", elem: i, message: String(e) });
        } finally {
          if (writer !== null) {
            try {
              writer.close();
            } catch (e) {}
          }
        }
      }
    }
    APU.emit({ type: "done", ok: true, total: total });
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
