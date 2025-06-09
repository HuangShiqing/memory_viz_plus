importScripts('https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js');
importScripts('https://cdnjs.cloudflare.com/ajax/libs/msgpack-lite/0.1.26/msgpack.min.js');
onmessage = function(e) {
    try {
      const {buffer, page_idx} = e.data
      const compressed = new Uint8Array(buffer);
      const decompressed = pako.inflate(compressed);  
      const unpacked = msgpack.decode(decompressed);

      const offsetTable = unpacked.offset_table;
      const dataBlob = unpacked.data_blob; // Uint8Array
      
      const uniq = unpacked.uniq
      const default_devid = unpacked.default_devid
      const device_num = unpacked.device_num
      const pages_num = unpacked.pages_num

      // 取device_idx、page_idx
      const [start, length] = offsetTable[default_devid][page_idx];
      const pageObj = msgpack.decode(dataBlob.slice(start, start + length));
      postMessage({"data":pageObj,
                   "uniq":uniq,
                   "default_devid":default_devid,
                   "device_num":device_num,
                   "pages_num":pages_num});
    } catch (err) {
      postMessage({error: err.message});
    }
  };