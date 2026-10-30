"""极简 MMKV 只读解析器（用于分析微信本地配置存储）。

MMKV 文件结构：
  [actualSize(4)][protobuf-encoded root Buffer]
protobuf:
  repeated Buffer kv { key: bytes(1) value: bytes(2) }
Buffer (长度前缀 varint + 内容)
本工具只做**读取与打印**，不改文件。

用法：
    python mmkv_dump.py <mmkv文件路径> [--grep KEY] [--max N]
"""
from __future__ import annotations

import os
import sys


def read_varint(buf: bytes, i: int):
    """返回 (value, new_i)。"""
    result = 0
    shift = 0
    while True:
        if i >= len(buf):
            raise ValueError("varint 越界")
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint 过长")
    return result, i


def parse_protobuf(buf: bytes):
    """解析出 {field_no: [values]}。"""
    out = {}
    i = 0
    while i < len(buf):
        key, i = read_varint(buf, i)
        field = key >> 3
        wt = key & 0x07
        if wt == 0:
            v, i = read_varint(buf, i)
        elif wt == 1:
            v = buf[i:i + 8]
            i += 8
        elif wt == 2:
            ln, i = read_varint(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wt == 5:
            v = buf[i:i + 4]
            i += 4
        else:
            raise ValueError("未知 wire type %d @%d" % (wt, i))
        out.setdefault(field, []).append(v)
    return out


def dump(path: str, grep: str = None, maxn: int = 0):
    with open(path, "rb") as f:
        data = f.read()
    actual = int.from_bytes(data[:4], "little")
    body = data[4:actual]
    fields = parse_protobuf(body)
    # field 1 = repeated Buffer kv
    kvs = fields.get(1, [])
    n = 0
    hits = 0
    for kvbuf in kvs:
        kv = parse_protobuf(kvbuf)
        keyb = (kv.get(1) or [b""])[0]
        valb = (kv.get(2) or [b""])[0]
        try:
            k = keyb.decode("utf-8")
        except Exception:
            k = repr(keyb)
        if grep and grep.lower() not in k.lower():
            continue
        hits += 1
        n += 1
        # 值可能是嵌套 protobuf，也可能是原始字节
        try:
            vs = valb.decode("utf-8")
            if not vs.isprintable() or len(vs) > 120:
                vs = valb.hex()[:240]
        except Exception:
            vs = valb.hex()[:240]
        print("  %-52s = %s" % (k, vs))
        if maxn and n >= maxn:
            break
    print("  -- 共 %d 个 kv（文件 %d B, actualSize %d）" % (len(kvs), len(data), actual))
    return hits


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    grep = None
    maxn = 0
    for a in sys.argv[1:]:
        if a.startswith("--grep"):
            grep = a.split("=", 1)[1] if "=" in a else None
        elif a.startswith("--max"):
            maxn = int(a.split("=", 1)[1]) if "=" in a else 0
    if not args:
        print(__doc__)
        return 1
    for p in args:
        print("=== %s ===" % p)
        try:
            dump(p, grep, maxn)
        except Exception as e:
            print("  解析失败：%r" % (e,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
