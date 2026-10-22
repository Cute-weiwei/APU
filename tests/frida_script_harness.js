// Execute the shipped scripts against synthetic 32/64-bit ART memory.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const scriptDir = path.resolve(__dirname, '../src/apk_unpack/scripts');
for (const width of [4, 8]) {
  const memory = new Map();
  const dexAddresses = new Set();
  const writes = new Map();
  const events = [];
  class Pointer {
    constructor(address) { this.address = Number(address); }
    add(offset) { return new Pointer(this.address + offset); }
    isNull() { return this.address === 0; }
    toString() { return '0x' + this.address.toString(16); }
    readPointer() {
      if (!memory.has(this.address)) throw Error('unmapped pointer');
      return new Pointer(memory.get(this.address));
    }
    readU32() { assert.equal(width, 4); return memory.get(this.address); }
    readU64() { assert.equal(width, 8); return memory.get(this.address); }
  }
  const loaders = [0, 1].map(index => {
    const cookie = 0x20000 + index * 0x1000;
    const begin = 0x80000 + index * 0x1000;
    memory.set(cookie + width, begin);
    memory.set(cookie + width * 2, 128);
    dexAddresses.add(begin);
    return {
      toString: () => 'loader-' + index,
      pathList: {dexElements: [{dexFile: {mCookie: [0, cookie], mFileName: 'app-' + index + '.dex'}, path: 'app.dex'}]},
    };
  });
  const context = {
    Process: {pointerSize: width}, ptr: value => new Pointer(value),
    APU: {
      cfg: {}, emit: event => events.push(event), ensureDir: () => '/out',
      waitForApp: callback => callback({getClassLoader: () => loaders[0]}),
      dexMagicOk: pointer => dexAddresses.has(pointer.address),
      writeBytes: (pointer, size, file) => { assert.equal(size, 128); writes.set(file, pointer.address); return true; },
    },
    Java: {
      perform: callback => callback(), cast: object => object,
      enumerateClassLoadersSync: () => loaders,
      use: name => name === 'java.lang.reflect.Array'
        ? {getLength: array => array.length, get: (array, i) => array[i], getLong: (array, i) => array[i]}
        : {class: {getDeclaredField: key => ({setAccessible() {}, get: object => object[key] ?? null})}},
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(scriptDir, 'dump_cookie.js'), 'utf8'), context);
  assert.equal(events.at(-1).type, 'done');
  assert.equal(events.at(-1).ok, true);
  assert.equal(events.at(-1).saved, 2, `both ${width * 8}-bit DEX must be recovered`);
  assert.equal(writes.size, 2, 'different classloaders must not overwrite each other');
  assert.deepEqual([...writes.values()], [...dexAddresses]);

  const signatures = {};
  const nativeContext = {
    Process: {pointerSize: width, id: 1, getModuleByName: () => ({getExportByName: name => name})},
    Frida: {version: 'fake'}, Memory: {allocUtf8String: value => value},
    console: {log() {}}, setTimeout() {},
    NativeFunction: function (name, result, args) {
      signatures[name] = {result, args: Array.from(args)};
      if (name === 'fopen') return () => ({isNull: () => false});
      if (name === 'fwrite') return (base, size, count) => count;
      return () => 0;
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(scriptDir, 'preamble.js'), 'utf8'), nativeContext);
  assert.equal(nativeContext.APU.writeBytes({}, 128, '/out/file.dex'), true);
  const sizeType = width === 4 ? 'uint' : 'uint64';
  assert.deepEqual(signatures.fwrite, {result: sizeType, args: ['pointer', sizeType, sizeType, 'pointer']});
}
console.log('32/64-bit extraction, loader isolation and fwrite ABI passed');
