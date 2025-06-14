importScripts('https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js');
importScripts('https://cdnjs.cloudflare.com/ajax/libs/msgpack-lite/0.1.26/msgpack.min.js');
onmessage = function(e) {
    try {
      const {buffer, page_idx} = e.data

      // 1. 读取 header_size（前4字节）
      const dataView = new DataView(buffer);
      const header_size = dataView.getUint32(0, true); // Little endian

      const uniq = [];//TODO:
      // 2. 读取 header 区并解析成对象
      const header_bytes = new Uint8Array(buffer, 4, header_size);
      const header_str = new TextDecoder().decode(header_bytes);
      const header = JSON.parse(header_str);
      const avail_device = header.avail_device
      const pages_num = header.pages_num
      const default_devid = header.default_devid

      // 3. 计算数据区起始位置
      const dataOffset = 4 + header_size;

      // 4. 读取 uniq_frames
      const [ot_start, ot_len] = header.uniq_frames_offset;
      const offset_table_zlib = new Uint8Array(buffer, dataOffset + ot_start, ot_len);
      const uniq_frames_obj = msgpack.decode(pako.inflate(offset_table_zlib));

      // 5. 读取具体的某一页（比如第 device_idx 个设备，第 page_idx 页）
      const [page_start, page_len] = header.offset[default_devid][page_idx];
      const page_zlib = new Uint8Array(buffer, dataOffset + page_start, page_len);
      // 6. 解压并解包
      const page_bytes = pako.inflate(page_zlib);
      // 假设使用 msgpack-lite
      const page_obj = msgpack.decode(page_bytes);
      postMessage({"data":page_obj,
                   "uniq_frames":uniq_frames_obj,
                   "default_devid":default_devid,
                   "avail_device":avail_device,
                   "pages_num":pages_num});
    } catch (err) {
      postMessage({error: err.message});
    }
  };