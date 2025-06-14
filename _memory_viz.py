# mypy: allow-untyped-defs
import pickle
import sys
import os
import io
import subprocess
import json
from functools import lru_cache
from typing import Any
from itertools import groupby
import base64
import warnings
import operator
import msgpack
import zlib
import struct
from tqdm import tqdm

cache = lru_cache(None)

__all__ = ["format_flamegraph", "segments", "memory", "compare"]

def _frame_fmt(f, full_filename=False):
    i = f['line']
    fname = f['filename']
    if not full_filename:
        fname = fname.split('/')[-1]
    func = f['name']
    return f'{fname}:{i}:{func}'

@cache
def _frame_filter(name, filename):
    omit_functions = [
        "unwind::unwind",
        "CapturedTraceback::gather",
        "gather_with_cpp",
        "_start",
        "__libc_start_main",
        "PyEval_",
        "PyObject_",
        "PyFunction_",
    ]
    omit_filenames = [
        "core/boxing",
        "/Register",
        "/Redispatch",
        "pythonrun.c",
        "Modules/main.c",
        "Objects/call.c",
        "Objects/methodobject.c",
        "pycore_ceval.h",
        "ceval.c",
        "cpython/abstract.h",
    ]
    for of in omit_functions:
        if of in name:
            return False
    for of in omit_filenames:
        if of in filename:
            return False
    return True

def _frames_fmt(frames, full_filename=False, reverse=False):
    if reverse:
        frames = reversed(frames)
    return [_frame_fmt(f, full_filename) for f in frames if _frame_filter(f['name'], f['filename'])]

def _block_extra_legacy(b):
    if 'history' in b:
        frames = b['history'][0].get('frames', [])
        real_size = b['history'][0]['real_size']
    else:
        real_size = b.get('requested_size', b['size'])
        frames = []
    return frames, real_size

def _block_extra(b):
    if 'frames' not in b:
        # old snapshot format made it more complicated to get frames/allocated size
        return _block_extra_legacy(b)
    return b['frames'], b['requested_size']

def format_flamegraph(flamegraph_lines, flamegraph_script=None):
    if flamegraph_script is None:
        flamegraph_script = f'/tmp/{os.getuid()}_flamegraph.pl'
    if not os.path.exists(flamegraph_script):
        import urllib.request
        print(f"Downloading flamegraph.pl to: {flamegraph_script}")
        urllib.request.urlretrieve(
            'https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl', flamegraph_script)
        subprocess.check_call(['chmod', '+x', flamegraph_script])
    args = [flamegraph_script, '--countname', 'bytes']
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, encoding='utf-8')
    assert p.stdin is not None
    assert p.stdout is not None
    p.stdin.write(flamegraph_lines)
    p.stdin.close()
    result = p.stdout.read()
    p.stdout.close()
    p.wait()
    assert p.wait() == 0
    return result

def _write_blocks(f, prefix, blocks):
    def frames_fragment(frames):
        if not frames:
            return "<non-python>"
        return ';'.join(_frames_fmt(frames, reverse=True))
    for b in blocks:
        if 'history' not in b:
            frames, accounted_for_size = _block_extra(b)
            f.write(f'{prefix};{b["state"]};{frames_fragment(frames)} {accounted_for_size}\n')
        else:
            accounted_for_size = 0
            for h in b['history']:
                sz = h['real_size']
                accounted_for_size += sz
                if 'frames' in h:
                    frames = h['frames']
                    f.write(f'{prefix};{b["state"]};{frames_fragment(frames)} {sz}\n')
                else:
                    f.write(f'{prefix};{b["state"]};<no-context> {sz}\n')
        gaps = b['size'] - accounted_for_size
        if gaps:
            f.write(f'{prefix};{b["state"]};<gaps> {gaps}\n')

def segments(snapshot, format_flamegraph=format_flamegraph):
    f = io.StringIO()
    for seg in snapshot['segments']:
        prefix = f'stream_{seg["stream"]};seg_{seg["address"]}'
        _write_blocks(f, prefix, seg['blocks'])
    return format_flamegraph(f.getvalue())

def memory(snapshot, format_flamegraph=format_flamegraph):
    f = io.StringIO()
    for seg in snapshot['segments']:
        prefix = f'stream_{seg["stream"]}'
        _write_blocks(f, prefix, seg['blocks'])
    return format_flamegraph(f.getvalue())

def compare(before, after, format_flamegraph=format_flamegraph):
    def _seg_key(seg):
        return (seg['address'], seg['total_size'])

    def _seg_info(seg):
        return f'stream_{seg["stream"]};seg_{seg["address"]}'

    f = io.StringIO()

    before_segs = {_seg_key(seg) for seg in before}
    after_segs = {_seg_key(seg) for seg in after}

    print(f'only_before = {[a for a, _ in (before_segs - after_segs)]}')
    print(f'only_after = {[a for a, _ in (after_segs - before_segs)]}')

    for seg in before:
        if _seg_key(seg) not in after_segs:
            _write_blocks(f, f'only_before;{_seg_info(seg)}', seg['blocks'])

    for seg in after:
        if _seg_key(seg) not in before_segs:
            _write_blocks(f, f'only_after;{_seg_info(seg)}', seg['blocks'])

    return format_flamegraph(f.getvalue())

def _format_size(num):
    # https://stackoverflow.com/questions/1094841/get-human-readable-version-of-file-size
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}B"
        num /= 1024.0
    return f"{num:.1f}YiB"

class Bytes:
    def __init__(self, value):
        self.value = value

    def __add__(self, rhs):
        return Bytes(self.value + rhs)

    def __repr__(self):
        return _format_size(self.value)

def calc_active(seg):
    return sum(b['size'] for b in seg['blocks'] if b['state'] == 'active_allocated')

def _report_free(free_external, free_internal):
    total = free_external + free_internal
    suffix = ''
    if total != 0:
        pct = (free_internal / total) * 100
        suffix = f' ({pct:.1f}% internal)'
    return f'{Bytes(total)}{suffix}'

PAGE_SIZE = 1024 * 1024 * 20
legend = f"""\

Legend:
    [a     ] - a segment in the allocator
     ^-- a page {Bytes(PAGE_SIZE)} of memory in the segment
    a-z: pages filled with a single block's content
    ' ': page is completely free
    *: page if completely full with multiple blocks
    0-9: page is partially full with tensors of multiple blocks (9 == 90% full)
    (X% internal) - of the free memory, X% is free because we rounded the size of the allocation.
"""

def segsum(data):
    r"""Visually reports how the allocator has filled its segments.

    This printout can help debug fragmentation issues since free fragments
    will appear as gaps in this printout.  The amount of free space is reported
    for each segment.
    We distinguish between internal free memory which occurs because the
    allocator rounds the allocation size, and external free memory, which are
    the gaps between allocations in a segment.
    Args:
        data: snapshot dictionary created from _snapshot()
    """
    segments = []
    out = io.StringIO()
    out.write(f"Summary of segments >= {Bytes(PAGE_SIZE)} in size\n")
    total_reserved = 0
    total_allocated = 0
    free_external = 0
    free_internal = 0
    for seg in sorted(data['segments'], key=lambda x: (x['total_size'], calc_active(x))):
        total_reserved += seg['total_size']

        seg_free_external = 0
        seg_free_internal = 0
        seg_allocated = 0
        all_ranges = []
        boffset = 0
        for b in seg['blocks']:
            active = b['state'] == 'active_allocated'
            if active:
                _, allocated_size = _block_extra(b)
                all_ranges.append((boffset, allocated_size, True))
                seg_allocated += allocated_size
                seg_free_internal += b['size'] - allocated_size
            else:
                seg_free_external += b['size']

            boffset += b['size']

        total_allocated += seg_allocated
        free_external += seg_free_external
        free_internal += seg_free_internal

        nseg = (seg['total_size'] - 1) // PAGE_SIZE + 1
        occupied = [' ' for _ in range(nseg)]
        frac = [0.0 for _ in range(nseg)]
        active_size = 0
        for i, (start_, size, active) in enumerate(all_ranges):
            active_size += size
            finish_ = (start_ + size)
            start = start_ // PAGE_SIZE
            finish = (finish_ - 1) // PAGE_SIZE + 1
            m = chr(ord('a' if active else 'A') + (i % 26))
            for j in range(start, finish):
                s = max(start_, j * PAGE_SIZE)
                e = min(finish_, (j + 1) * PAGE_SIZE)
                frac[j] += (e - s) / PAGE_SIZE
                if occupied[j] != ' ':
                    occupied[j] = '0123456789*'[int(frac[j] * 10)]
                else:
                    occupied[j] = m
        stream = '' if seg['stream'] == 0 else f', stream_{seg["stream"]}'
        body = ''.join(occupied)
        assert seg_free_external + seg_free_internal + seg_allocated == seg['total_size']
        stream = f' stream_{seg["stream"]}' if seg['stream'] != 0 else ''
        if seg['total_size'] >= PAGE_SIZE:
            out.write(f'[{body}] {Bytes(seg["total_size"])} allocated, '
                      f'{_report_free(seg_free_external, seg_free_internal)} free{stream}\n')
    out.write(f'segments: {len(data["segments"])}\n')
    out.write(f'total_reserved: {Bytes(total_reserved)}\n')
    out.write(f'total_allocated: {Bytes(total_allocated)}\n')
    internal_external = f' ({Bytes(free_internal)} internal + {Bytes(free_external)} external)' if free_internal else ''
    out.write(f'total_free: {_report_free(free_external, free_internal)}\n')
    out.write(legend)
    assert free_internal + free_external + total_allocated == total_reserved
    return out.getvalue()

def trace(data):
    out = io.StringIO()

    def format(entries):
        segment_intervals : list = []
        segment_addr_to_name = {}
        allocation_addr_to_name = {}

        free_names : list = []
        next_name = 0

        def _name():
            nonlocal next_name
            if free_names:
                return free_names.pop()
            r, m = next_name // 26, next_name % 26
            next_name += 1
            return f'{chr(ord("a") + m)}{"" if r == 0 else r}'

        def find_segment(addr):
            for name, saddr, size in segment_intervals:
                if addr >= saddr and addr < saddr + size:
                    return name, saddr
            for i, seg in enumerate(data['segments']):
                saddr = seg['address']
                size = seg['allocated_size']
                if addr >= saddr and addr < saddr + size:
                    return f'seg_{i}', saddr
            return None, None
        count = 0
        out.write(f'{len(entries)} entries\n')


        total_reserved = 0
        for seg in data['segments']:
            total_reserved += seg['total_size']

        for count, e in enumerate(entries):
            if e['action'] == 'alloc':
                addr, size = e['addr'], e['size']
                n = _name()
                seg_name, seg_addr = find_segment(addr)
                if seg_name is None:
                    seg_name = "MEM"
                    offset = addr
                else:
                    offset = addr - seg_addr
                out.write(f'{n} = {seg_name}[{offset}:{Bytes(size)}]\n')
                allocation_addr_to_name[addr] = (n, size, count)
                count += size
            elif e['action'] == 'free_requested':
                addr, size = e['addr'], e['size']
                name, _, _ = allocation_addr_to_name.get(addr, (addr, None, None))
                out.write(f'del {name} # {Bytes(size)}\n')
            elif e['action'] == 'free_completed':
                addr, size = e['addr'], e['size']
                count -= size
                name, _, _ = allocation_addr_to_name.get(addr, (addr, None, None))
                out.write(f'# free completed for {name} {Bytes(size)}\n')
                if name in allocation_addr_to_name:
                    free_names.append(name)
                    del allocation_addr_to_name[name]
            elif e['action'] == 'segment_alloc':
                addr, size = e['addr'], e['size']
                name = _name()
                out.write(f'{name} = cudaMalloc({addr}, {Bytes(size)})\n')
                segment_intervals.append((name, addr, size))
                segment_addr_to_name[addr] = name
            elif e['action'] == 'segment_free':
                addr, size = e['addr'], e['size']
                name = segment_addr_to_name.get(addr, addr)
                out.write(f'cudaFree({name}) # {Bytes(size)}\n')
                if name in segment_addr_to_name:
                    free_names.append(name)
                    del segment_addr_to_name[name]
            elif e['action'] == 'oom':
                size = e['size']
                free = e['device_free']
                out.write(f'raise OutOfMemoryError # {Bytes(size)} requested, {Bytes(free)} free in CUDA\n')
            else:
                out.write(f'{e}\n')
        out.write(f"TOTAL MEM: {Bytes(count)}")
    for i, d in enumerate(data['device_traces']):
        if d:
            out.write(f'Device {i} ----------------\n')
            format(d)
    return out.getvalue()


_memory_viz_template = r"""
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<script type="module">
import {add_local_files} from "https://cdn.jsdelivr.net/gh/pytorch/pytorch@main/torch/utils/viz/MemoryViz.js"
const local_files = $SNAPSHOT
add_local_files(local_files, $VIZ_KIND)
</script>
</body>
"""

def process_alloc_data(snapshot, device, plot_segments, max_entries, pages_num=1):
    elements = []
    initially_allocated = []
    actions = []
    addr_to_alloc = {}

    alloc = 'segment_alloc' if plot_segments else 'alloc'
    if plot_segments:
        free, free_completed = 'segment_free', 'segment_free'
    else:
        free, free_completed = 'free', 'free_completed'

    if len(snapshot['device_traces'][device]) == 0:
        return []
    # 1. first pass: build elements and actions
    for e in tqdm(snapshot['device_traces'][device], desc = f"dev{device}预处理"):
        action = e['action']
        if action == alloc:
            elements.append(e)
            addr_to_alloc[e['addr']] = len(elements) - 1
            actions.append(len(elements) - 1)
        elif action == free or action == free_completed:
            if e['addr'] in addr_to_alloc:
                actions.append(addr_to_alloc[e['addr']])
                del addr_to_alloc[e['addr']]
            else:
                elements.append(e)
                initially_allocated.append(len(elements) - 1)
                actions.append(len(elements) - 1)
        else:
            continue

    # 2. second pass: add missing allocations from segments
    for seg in snapshot['segments']:
        if seg['device'] != device:
            continue
        if plot_segments:
            if seg['address'] not in addr_to_alloc:
                element = {
                    'action': 'alloc',
                    'addr': seg['address'],
                    'size': seg['total_size'],
                    'frames': [],
                    'stream': seg['stream'],
                    'version': seg['version'],
                }
                elements.append(element)
                initially_allocated.append(len(elements) - 1)
        else:
            for b in seg['blocks']:
                if b['state'] == 'active_allocated' and b['address'] not in addr_to_alloc:
                    element = {
                        'action': 'alloc',
                        'addr': b['address'],
                        'size': b['requested_size'],
                        'frames': b['frames'],
                        'stream': seg['stream'],
                        'version': b['version'],
                    }
                    elements.append(element)
                    initially_allocated.append(len(elements) - 1)

    initially_allocated = initially_allocated[::-1]

    if len(actions) == 0 and len(initially_allocated) > 0:
        actions.append(initially_allocated.pop())

    current = []
    current_data = []
    data_out = []
    max_size = 0

    total_mem = 0
    total_summarized_mem = 0
    timestep = 0

    max_at_time = []

    summarized_mem = {
        'elem': 'summarized',
        'timesteps': [],
        'offsets': [total_mem],
        'size': [],
        'color': 0,
    }
    summarized_elems = {}

    def advance(n):
        nonlocal timestep
        summarized_mem['timesteps'].append(timestep)
        summarized_mem['offsets'].append(total_mem)
        summarized_mem['size'].append(total_summarized_mem)
        timestep += n
        for _ in range(n):
            max_at_time.append(total_mem + total_summarized_mem)

    # sort elements by size, descending, keep only max_entries
    sizes = sorted(
        [(elem.get('size', 0), idx) for idx, elem in enumerate(elements)],
        key=lambda x: -x[0]
    )
    draw_elem = {e: True for _s, e in sizes[:max_entries]}

    def add_allocation(elem):
        nonlocal total_mem, total_summarized_mem, timestep
        element_obj = elements[elem]
        size = element_obj.get('size', 0)
        current.append(elem)
        color = elem
        # category/color logic
        if snapshot.get('categories', []):
            color = snapshot['categories'].index(element_obj.get('category', 'unknown')) \
                if element_obj.get('category', 'unknown') in snapshot['categories'] \
                else 0
        e = {
            'elem': elem,
            'timesteps': [timestep],
            'offsets': [total_mem],
            'size': size,
            'color': color,
        }
        current_data.append(e)
        data_out.append(e)
        total_mem += size
        element_obj['max_allocated_mem'] = total_mem + total_summarized_mem

    for elem in initially_allocated:
        if elem in draw_elem:
            add_allocation(elem)
        else:
            total_summarized_mem += elements[elem].get('size', 0)
            summarized_elems[elem] = True

    for elem in actions:
        size = elements[elem].get('size', 0)
        if elem not in draw_elem:
            if summarized_elems.get(elem):
                advance(1)
                total_summarized_mem -= size
                summarized_elems[elem] = None
            else:
                total_summarized_mem += size
                summarized_elems[elem] = True
                advance(1)
            continue
        # Find last index in current where x == elem
        try:
            idx = len(current) - 1 - current[::-1].index(elem)
        except ValueError:
            idx = -1
        if idx == -1:
            add_allocation(elem)
            advance(1)
        else:
            advance(1)
            removed = current_data[idx]
            removed['timesteps'].append(timestep)
            removed['offsets'].append(removed['offsets'][-1])
            del current[idx]
            del current_data[idx]
            if idx < len(current):
                for j in range(idx, len(current)):
                    e = current_data[j]
                    e['timesteps'].append(timestep)
                    e['offsets'].append(e['offsets'][-1])
                    e['timesteps'].append(timestep + 3)
                    e['offsets'].append(e['offsets'][-1] - size)
                advance(3)
            total_mem -= size
        max_size = max(total_mem + total_summarized_mem, max_size)

    for elem in current_data:
        elem['timesteps'].append(timestep)
        elem['offsets'].append(elem['offsets'][-1])
    data_out.append(summarized_mem)

    N = len(max_at_time)
    page_points = [int(round(i * N / pages_num)) for i in range(pages_num + 1)]
    page_data_out = [[] for _ in range(pages_num)]
    page_elements_out = [[] for _ in range(pages_num)]
    # 新增分割 max_at_time
    page_max_at_time = []
    for i in range(pages_num):
        left, right = page_points[i], page_points[i + 1]
        page_max_at_time.append(max_at_time[left:right])

    for item in data_out[:-1]:#skip summarized
        timesteps = item['timesteps']
        min_t = min(timesteps)
        max_t = max(timesteps)

        for i in range(pages_num):
            new_item = None
            left, right = page_points[i], page_points[i + 1]
            # 完全在当前区间
            if min_t >= left and max_t <= right:
                new_item = item.copy()
                new_item['timesteps'] = [t - left for t in item['timesteps']]
            # 完全不在当前区间
            elif max_t <= left or min_t >= right:
                continue
            # 完全包裹分段
            elif min_t <= left and max_t >= right:
                ts_full = item['timesteps']
                ofs_full = item['offsets']
                ts, ofs = [], []
                for t, o in zip(ts_full, ofs_full):
                    if left <= t <= right:
                        ts.append(t)
                        ofs.append(o)
                # 补首端
                if not ts or ts[0] > left:
                    # 取第一个大于left的点的offset
                    for j, t in enumerate(ts_full):
                        if t > left:
                            ts = [left] + ts
                            ofs = [ofs_full[j]] + ofs
                            break
                # 补尾端
                if not ts or ts[-1] < right:
                    # 取最后一个小于right的点的offset
                    for j in reversed(range(len(ts_full))):
                        if ts_full[j] < right:
                            ts.append(right)
                            ofs.append(ofs_full[j])
                            break
                # 按要求减去 left
                if len(ts) >= 2:
                    new_item = item.copy()
                    new_item['timesteps'] = [t - left for t in ts]
                    new_item['offsets'] = ofs
            # 跨区间
            else:
                # 找区间内的timesteps和offsets
                ts, ofs = [], []
                ts_full = item['timesteps']
                ofs_full = item['offsets']
                for t, o in zip(ts_full, ofs_full):
                    if left <= t <= right:
                        ts.append(t)
                        ofs.append(o)
                # 补首端
                if ts and ts[0] > left and min_t < left:
                    ts = [left] + ts
                    idx = ts_full.index(ts[1])
                    ofs = [ofs_full[idx]] + ofs
                # 补尾端
                if ts and ts[-1] < right and max_t > right:
                    ts.append(right)
                    idx = ts_full.index(ts[-2])
                    ofs.append(ofs_full[idx])
                # 按要求减去 left
                if len(ts) >= 2:
                    new_item = item.copy()
                    new_item['timesteps'] = [t - left for t in ts]
                    new_item['offsets'] = ofs

            if new_item:
                page_data_out[i].append(new_item)
                page_elements_out[i].append(elements[new_item['elem']])
                new_item['elem'] = len(page_elements_out[i]) - 1

    return [ {
        'page_num': pages_num,
        'max_size': max_size,
        'allocations_over_time': page_data_out[i],
        'max_at_time': page_max_at_time[i],
        'elements': page_elements_out[i]
        } for i in range(pages_num)]
    # return {
    #     'page_num': pages_num,
    #     'max_size': max_size,
    #     'page_allocations_over_time': page_data_out,
    #     "page_max_timestep": page_max_timestep,
    #     'summarized_mem': summarized_mem,
    #     'elements_length': len(elements),
    #     'elements': elements #TODO: split page
    # }

def _format_viz(data, viz_kind, device, pages_num):
    # 去重
    seen = {}
    unique = []
    max_traces_num = -1
    default_devid = 0
    avail_device = []
    for device_idx in range(len(data["device_traces"])):
        if len(data["device_traces"][device_idx]) == 0: #skip empty
            continue
        avail_device.append(device_idx)
        if len(data["device_traces"][device_idx]) > max_traces_num:
            max_traces_num = len(data["device_traces"][device_idx])
            default_devid = device_idx
        for alloc_idx in tqdm(range(len(data["device_traces"][device_idx])), desc = f"dev{device_idx}去重"):
            frames = data["device_traces"][device_idx][alloc_idx]["frames"]
            keys = ["filename", "line", "name"]
            for idx, d in enumerate(frames):
                if isinstance(d, int): #skip shared memory
                    break
                t = tuple(d[k] for k in keys)
                if t not in seen:
                    seen[t] = len(unique)
                    unique.append(d)
                frames[idx] = seen[t]

    # print("[hsq] delete the frames")
    fake_frame = {"name":"hsq","filename":"hsq", "line":0}
    # for device_idx in range(len(data["device_traces"])):
    #     for alloc_idx in range(len(data["device_traces"][device_idx])):
    #         data["device_traces"][device_idx][alloc_idx]["frames"] = [fake_frame]
    
    for segment in data["segments"]:
        if len(segment['frames']):
            segment['frames'] = [fake_frame]
        for block in segment["blocks"]:
            if len(block['frames']):
                block['frames'] = [fake_frame]
    data["external_annotations"] = []

    data_outs =[]
    for device_idx in range(len(data["device_traces"])):
        data_out = process_alloc_data(data, device_idx, False, None, pages_num=pages_num)
        data_outs.append(data_out)

    current = 0
    # 1. uniq_frames 压缩
    uniq_frames_bytes = msgpack.packb(unique)
    uniq_frames_zlib = zlib.compress(uniq_frames_bytes)
    uniq_frames_offset = (current, len(uniq_frames_zlib), 'uniq_frames_offset')
    current += len(uniq_frames_zlib)

    pages_offset = []
    # 2. 各page独立压缩
    pages_zlib = []
    for device_idx, device_pages in enumerate(data_outs):
        device_offsets = []
        device_pages_zlib = []
        for page_idx, page_data in enumerate(device_pages):
            page_bytes = msgpack.packb(page_data)
            page_zlib = zlib.compress(page_bytes)
            device_offsets.append((current, len(page_zlib), f'page_{device_idx}_{page_idx}'))
            device_pages_zlib.append(page_zlib)
            current += len(page_zlib)
        pages_offset.append(device_offsets)
        pages_zlib.append(device_pages_zlib)
    # 3. 头部信息
    # offsets: [[(start, length, "page_{device_idx}_{page_idx}"), ...], ...]
    header = {
        "uniq_frames_offset": uniq_frames_offset,
        "offset": pages_offset,
        "pages_num": pages_num,
        "avail_device": avail_device,
        "default_devid": default_devid
    }
    header_bytes = json.dumps(header).encode()
    header_size = len(header_bytes)

    # 先拼接所有需要写入的数据
    header_size_bytes = struct.pack('<I', header_size)
    pages_bytes = b''.join(
        page_zlib
        for device_pages_zlib in pages_zlib
        for page_zlib in device_pages_zlib
    )
    all_bytes = header_size_bytes + header_bytes + uniq_frames_zlib + pages_bytes
    return all_bytes
    # if device is not None:
    #     warnings.warn(
    #         'device argument is deprecated, plots now contain all device',
    #         FutureWarning,
    #         stacklevel=3,
    #     )
    # buffer = pickle.dumps(data)
    # buffer += b'\x00' * (3 - len(buffer) % 3)
    # # Encode the buffer with base64
    # encoded_buffer = base64.b64encode(buffer).decode('utf-8')

    # json_format = json.dumps([{"name": 'snapshot.pickle', "base64": encoded_buffer}])
    # return _memory_viz_template.replace('$VIZ_KIND', repr(viz_kind)) \
    #                            .replace('$SNAPSHOT', json_format)

def trace_plot(data, device=None, pages_num=1, plot_segments=False):
    """Generate a visualization over time of the memory usage recorded by the trace as an html file.

    Args:
        data: Memory snapshot as generated from torch.cuda.memory._snapshot()
        device (torch.device, optional): Generate the trace for this device, needed if multiple devices have allocations.
        plot_segments (bool, optional): Plots memory returned from cudaMalloc, rather than individual allocations.
                                        Defaults to False.

    Returns:
        str: HTML of visualization
    """
    return _format_viz(data, 'Active Memory Timeline' if not plot_segments else 'Active Cached Memory Timeline', device, pages_num)


def _profile_to_snapshot(profile):
    import torch
    from torch.profiler._memory_profiler import Action, TensorKey
    from torch._C._profiler import _EventType
    memory_profile = profile._memory_profile()

    allocation_stacks = {}
    for event in memory_profile._op_tree.sorted_nodes:
        if event.tag == _EventType.Allocation:
            parent = event.parent
            python_parents = []
            while parent:
                if parent.tag in (_EventType.PyCall, _EventType.PyCCall):
                    python_parents.append(parent)
                parent = parent.parent
            key = TensorKey.from_allocation(event.extra_fields)

            # Corner case: If allocation doesn't have an ID (can't prove it was used as a Tensor)
            #              key will be None. I should add some way to identify these, I just haven't yet.
            if key and event.extra_fields.alloc_size > 0:
                allocation_stacks[key] = python_parents


    device_count = torch.cuda.device_count()
    snapshot = {
        'device_traces': [[] for _ in range(device_count + 1)],
        'segments': [{'device': device,
                      'address': None,
                      'total_size': 0,
                      'stream': 0,
                      'blocks': []} for device in range(device_count + 1)]
    }

    def to_device(device):
        if device.type == 'cuda':
            return device.index
        else:
            return device_count

    def allocate(size, tensor_key, version, during_trace=True):
        device = to_device(tensor_key.device)
        addr = tensor_key.storage.ptr

        seg = snapshot['segments'][device]  # type: ignore[index]
        if seg['address'] is None or seg['address'] > addr:
            seg['address'] = addr
        seg['total_size'] = max(seg['total_size'], addr + size)  # record max addr for now, we will make it the size later
        category = memory_profile._categories.get(tensor_key, version)
        category = category.name.lower() if category is not None else "unknown"
        stack = allocation_stacks.get(tensor_key, ())
        stack = [{'filename': 'none', 'line': 0, 'name': p.name} for p in stack]
        r = {'action': 'alloc', 'addr': addr, 'size': size, 'stream': 0, 'frames': stack, 'category': category}
        if during_trace:
            snapshot['device_traces'][device].append(r)  # type: ignore[index]
        return r

    def free(alloc, device):
        for e in ('free_requested', 'free_completed'):
            snapshot['device_traces'][device].append({'action': e,  # type: ignore[index]
                                                      'addr': alloc['addr'],
                                                      'size': alloc['size'],
                                                      'stream': 0,
                                                      'frames': alloc['frames']})

    kv_to_elem = {}



    # create the device trace
    for time, action, (tensor_key, version), size in memory_profile.timeline:
        if not isinstance(tensor_key, TensorKey):
            continue
        if action == Action.CREATE:
            kv_to_elem[(tensor_key, version)] = allocate(size, tensor_key, version)
        elif action == Action.DESTROY:
            free(kv_to_elem.pop((tensor_key, version)), to_device(tensor_key.device))
        elif action == Action.INCREMENT_VERSION:
            free(kv_to_elem.pop((tensor_key, version)), to_device(tensor_key.device))
            kv_to_elem[(tensor_key, version + 1)] = allocate(size, tensor_key, version + 1)
        elif action == Action.PREEXISTING:
            kv_to_elem[(tensor_key, version)] = allocate(size, tensor_key, version, during_trace=False)


    # create the final snapshot state
    blocks_at_end = [(to_device(tensor_key.device), event['addr'], event['size'], event['frames'])
                     for (tensor_key, version), event in kv_to_elem.items()]
    for device, blocks in groupby(sorted(blocks_at_end), key=operator.itemgetter(0)):
        seg = snapshot['segments'][device]  # type: ignore[index]
        last_addr = seg['address']
        for _, addr, size, frames in blocks:
            if last_addr < addr:
                seg['blocks'].append({'size': addr - last_addr, 'state': 'inactive'})
            seg['blocks'].append({'size': size, 'state': 'active_allocated', 'requested_size': size, 'frames': frames})
            last_addr = addr + size
        if last_addr < seg['total_size']:
            seg['blocks'].append({'size': seg['total_size'] - last_addr, 'state': 'inactive'})

    snapshot['segments'] = [seg for seg in snapshot['segments'] if seg['blocks']]  # type: ignore[attr-defined]
    for seg in snapshot['segments']:  # type: ignore[attr-defined, name-defined, no-redef]
        seg['total_size'] -= seg['address']
        if not seg['blocks']:
            seg['blocks'].append({'size': seg['total_size'], 'state': 'inactive'})

    return snapshot

def profile_plot(profile, device=None):
    """Generate a visualization over time of the memory usage recorded by kineto memory profiling as an html file.

    Args:
        profile: profile as generated by `torch.profiler.profile(profile_memory=True)`
        device (torch.device, optional): Generate the trace for this device, needed if multiple devices have allocations.

    Returns:
        str: HTML of visualization
    """
    snapshot = _profile_to_snapshot(profile)
    return _format_viz(snapshot, 'Active Memory Timeline', device)


def segment_plot(data: Any, device=None):
    return _format_viz(data, 'Allocator State History', device)

if __name__ == "__main__":
    import os.path
    thedir = os.path.realpath(os.path.dirname(__file__))
    if thedir in sys.path:
        # otherwise we find cuda/random.py as random...
        sys.path.remove(thedir)
    import argparse

    fn_name = 'torch.cuda.memory._snapshot()'
    pickled = f'pickled memory statistics from {fn_name}'
    parser = argparse.ArgumentParser(description=f'Visualize memory dumps produced by {fn_name}')

    subparsers = parser.add_subparsers(dest='action')

    def _output(p):
        p.add_argument('-o', '--output', default='output.svg', help='flamegraph svg (default: output.svg)')

    description = 'Prints overall allocation statistics and a visualization of how the allocators segments are currently filled.'
    stats_a = subparsers.add_parser('stats', description=description)
    stats_a.add_argument('input', help=pickled)

    description = 'Prints buffer of the most recent allocation events embedded in the snapshot in a Pythonic style.'
    trace_a = subparsers.add_parser('trace', description=description)
    trace_a.add_argument('input', help=pickled)

    description = 'Generate a flamegraph that visualizes what memory is stored in each allocator segment (aka block)'
    segments_a = subparsers.add_parser('segments', description=description)
    segments_a.add_argument('input', help=pickled)
    _output(segments_a)

    description = "Generate a flamegraph the program locations contributing to CUDA memory usage."
    memory_a = subparsers.add_parser('memory', description=description)
    memory_a.add_argument('input', help=pickled)
    _output(memory_a)

    description = 'Generate a flamegraph that shows segments (aka blocks) that have been added ' \
        'or removed between two different memorys snapshots.'
    compare_a = subparsers.add_parser('compare', description=description)
    compare_a.add_argument('before', help=pickled)
    compare_a.add_argument('after', help=pickled)
    _output(compare_a)

    plots = (
        ("trace_plot", "Generate a visualization over time of the memory usage recorded by the trace as an html file."),
        ("segment_plot", "Visualize how allocations are packed into allocator segments at each point in a trace as an html file.")
    )
    for cmd, description in plots:
        trace_plot_a = subparsers.add_parser(cmd, description=description)
        trace_plot_a.add_argument('input', help=pickled)
        help = 'visualize trace from this device (default: chooses the only device with trace info or errors)'
        trace_plot_a.add_argument('-d', '--device', type=int, default=None, help=help)
        help = 'path to save the visualization(default: output.html)'
        trace_plot_a.add_argument('-o', '--output', default='output.html', help=help)
        help = 'split full trace_plot into multi pages to show(default: 1)'
        trace_plot_a.add_argument('-p', '--pages_num', type=int, default=1, help=help)
        if cmd == "trace_plot":
            help = 'visualize change to segments rather than individual allocations'
            trace_plot_a.add_argument('-s', '--segments', action='store_true', help=help)


    args = parser.parse_args()

    def _read(name):
        if name == '-':
            f = sys.stdin.buffer
        else:
            f = open(name, 'rb')
        data = pickle.load(f)
        if isinstance(data, list):  # segments only...
            data = {'segments': data, 'traces': []}
        return data

    def _write(name, data):
        with open(name, 'wb') as f:
            f.write(data)

    if args.action == 'segments':
        data = _read(args.input)
        _write(args.output, segments(data))
    elif args.action == 'memory':
        data = _read(args.input)
        _write(args.output, memory(data))
    elif args.action == 'stats':
        data = _read(args.input)
        print(segsum(data))
    elif args.action == 'trace':
        data = _read(args.input)
        print(trace(data))
    elif args.action == 'compare':
        before = _read(args.before)
        after = _read(args.after)
        _write(args.output, compare(before, after))
    elif args.action == 'trace_plot':
        data = _read(args.input)
        _write(args.output + '.zlib', trace_plot(data, device=args.device, pages_num=args.pages_num, plot_segments=args.segments))
    elif args.action == 'segment_plot':
        data = _read(args.input)
        _write(args.output, segment_plot(data, device=args.device))
