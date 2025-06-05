importScripts('https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js');
importScripts('https://cdnjs.cloudflare.com/ajax/libs/msgpack-lite/0.1.26/msgpack.min.js');
onmessage = function(e) {
    try {
      const compressed = new Uint8Array(e.data);
      const decompressed = pako.inflate(compressed);
      const unpacked = msgpack.decode(decompressed);
      // Worker 中只能postMessage结构化可序列化的数据
      postMessage({unpacked});
    } catch (err) {
      postMessage({error: err.message});
    }
  };