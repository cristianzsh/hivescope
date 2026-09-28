"""
System-context artifacts:
  Windows product key (DigitalProductId, legacy base-24 decode) (SOFTWARE)
  Crash dump + page file configuration                          (SYSTEM)
  Prefetch / SysMain (Superfetch) state                         (SYSTEM)
  Recently-written registry keys (mini timeline across hives)
"""

import heapq

from .core import (open_key, kval, svc_start_str)
from .model import Section, p_software, p_system

_PK_CHARS = "BCDFGHJKMPQRTVWXY2346789"


def _decode_product_key(dpid):
    if not isinstance(dpid, bytes) or len(dpid) < 67:
        return None
    key = bytearray(dpid[52:52 + 15])
    out = ""
    for i in range(24, -1, -1):
        cur = 0
        for j in range(14, -1, -1):
            cur = (cur << 8) | key[j]
            key[j] = cur // 24
            cur %= 24
        out = _PK_CHARS[cur] + out
    return "-".join(out[i:i + 5] for i in range(0, 25, 5))


def sec_product_key(software):
    s = Section("productkey", "System - Windows Product Key")
    rel = "Microsoft\\Windows NT\\CurrentVersion"
    k = open_key(software, rel)
    if k is None:
        s.note("CurrentVersion key not present.")
        return s
    dpid = kval(k, "DigitalProductId")
    key = _decode_product_key(dpid) if dpid else None
    s.path(p_software("Microsoft", "Windows NT", "CurrentVersion",
                      "DigitalProductId"))
    if key:
        s.kv([("Product key (legacy decode)", key),
              ("Product name", kval(k, "ProductName")),
              ("Product ID", kval(k, "ProductId"))])
        s.note("Base-24 decode is reliable for Windows 7 and earlier; "
               "Windows 8+ keys may differ.")
    else:
        s.note("DigitalProductId not present or not decodable.")
    return s


def sec_crash_pagefile(system, cs):
    s = Section("crash_pagefile", "System - Crash Dump & Page File")
    mm = open_key(system, cs + "\\Control\\Session Manager\\Memory Management")
    if mm is not None:
        s.sub("Memory management / page file")
        s.path(p_system(cs, "Control", "Session Manager", "Memory Management"))
        pf = kval(mm, "PagingFiles")
        s.kv([("PagingFiles", pf if not isinstance(pf, list)
               else " | ".join(pf)),
              ("ClearPageFileAtShutdown", kval(mm, "ClearPageFileAtShutdown")),
              ("ExistingPageFiles", kval(mm, "ExistingPageFiles"))])
    cc = open_key(system, cs + "\\Control\\CrashControl")
    if cc is not None:
        dmp = {0: "none", 1: "complete", 2: "kernel", 3: "small (minidump)",
               7: "automatic"}
        s.sub("Crash control")
        s.path(p_system(cs, "Control", "CrashControl"))
        s.kv([("CrashDumpEnabled",
               dmp.get(kval(cc, "CrashDumpEnabled"),
                       kval(cc, "CrashDumpEnabled"))),
              ("DumpFile", kval(cc, "DumpFile")),
              ("MinidumpDir", kval(cc, "MinidumpDir")),
              ("AutoReboot", kval(cc, "AutoReboot")),
              ("LogEvent", kval(cc, "LogEvent"))])
    if mm is None and cc is None:
        s.note("Memory management / crash control keys not present.")
    return s


def sec_prefetch(system, cs):
    s = Section("prefetch", "System - Prefetch / SysMain")
    pp = open_key(system, cs + "\\Control\\Session Manager\\Memory Management\\PrefetchParameters")
    ep = es = None
    if pp is not None:
        ep = kval(pp, "EnablePrefetcher")
        es = kval(pp, "EnableSuperfetch")
    lbl = {0: "disabled", 1: "apps", 2: "boot", 3: "apps+boot"}
    s.path(p_system(cs, "Control", "Session Manager", "Memory Management", "PrefetchParameters"))
    sysmain = open_key(system, cs + "\\Services\\SysMain")
    start = kval(sysmain, "Start") if sysmain is not None else None
    s.kv([("EnablePrefetcher", lbl.get(ep, ep)),
          ("EnableSuperfetch", lbl.get(es, es)),
          ("SysMain service start", svc_start_str(start)
           if start is not None else "(no SysMain service)")])
    if pp is None and sysmain is None:
        s.note("Prefetch/SysMain configuration not present.")
    return s


# Recently-written registry keys (mini timeline)
def _walk_recent(reg, label, heap, top_n, cap):
    """DFS every key, keeping the top-N by LastWrite in heap. The key path is
    built incrementally as we descend (parent path + child name) so we never
    call the O(depth) path() accessor per key."""
    if reg is None:
        return
    try:
        root = reg.root()
    except Exception:
        return
    stack = []
    try:
        for sk in root.subkeys():
            stack.append((sk, sk.name()))
    except Exception:
        return
    visited = 0
    push, replace = heapq.heappush, heapq.heapreplace
    while stack and visited < cap:
        k, path = stack.pop()
        visited += 1
        try:
            ts = k.timestamp()
        except Exception:
            ts = None
        if ts is not None:
            item = (ts, label, path)
            if len(heap) < top_n:
                push(heap, item)
            elif ts > heap[0][0]:
                replace(heap, item)
        try:
            for sk in k.subkeys():
                stack.append((sk, path + "\\" + sk.name()))
        except Exception:
            pass


def sec_reg_timeline(hive_pairs, top_n=250, cap_per_hive=3000000):
    s = Section("reg_timeline", "System - Recently Written Registry Keys")
    heap = []
    for label, reg in hive_pairs:
        _walk_recent(reg, label, heap, top_n, cap_per_hive)
    rows = []
    for ts, label, path in sorted(heap, key=lambda x: x[0], reverse=True):
        try:
            tss = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            tss = str(ts)
        rows.append((tss, label, path))
    if not rows:
        s.note("No key timestamps collected.")
        return s
    s.text("Top %d most-recently-written keys across the loaded hives "
           "(LastWrite time). Useful for pinning activity to a time window."
           % len(rows))
    s.table(["Key last written", "Hive", "Key path"], rows)
    return s
