# Import symbols from a CSV (Address,Name,...) into the current Ghidra program.
# "A::B::c" names are split into nested namespaces, template args (<...>) are respected.
# Same address with several names: first one becomes primary, the rest are extra labels.
#@category Symbol

import csv
import re
from ghidra.program.model.symbol import SourceType
from java.lang import Throwable

BASE = 0x7100000000
RENAME_EXISTING_FUNCTIONS = True    # rename/move functions that already exist at the address
CREATE_MISSING_FUNCTIONS = False    # createFunction() where no function exists

# Ghidra auto-generated names (FUN_..., LAB_..., DAT_..., thunk_FUN_...): not real symbols.
DEFAULT_NAME = re.compile(r"^(thunk_)?(FUN|LAB|DAT|SUB|UNK|PTR|EXT|OFF|ADR)_[0-9A-Fa-f]{6,}$")
# Ghidra switch-table labels (switchD_7100000000::caseD_0, ::default, switchdataD_...).
SWITCH_NAME = re.compile(r"(^|::)(switchD|caseD|switchdataD)_[0-9A-Fa-f]+(::|$)")

symtab = currentProgram.getSymbolTable()
mem = currentProgram.getMemory()
ns_cache = {}


def split_ns(name):
    """Split on '::' outside of <...>."""
    parts = []
    cur = ""
    depth = 0
    i = 0
    while i < len(name):
        c = name[i]
        if c == "<":
            depth += 1
        elif c == ">" and depth > 0:
            depth -= 1
        if depth == 0 and name.startswith("::", i):
            parts.append(cur)
            cur = ""
            i += 2
            continue
        cur += c
        i += 1
    parts.append(cur)
    return parts


def sanitize(name):
    return name.replace(" ", "_").replace(":", "_")


def clean(p):
    """Strip stray ':' / spaces from one name part (keep '::' inside template args)."""
    if "<" in p:
        return p.replace(" ", "_")
    return sanitize(p)


def get_ns(path):
    """path: list of namespace names (without leaf). Returns Namespace."""
    ns = currentProgram.getGlobalNamespace()
    key = ()
    for p in path:
        key = key + (p,)
        if key in ns_cache:
            ns = ns_cache[key]
            continue
        ns = symtab.getOrCreateNameSpace(ns, p, SourceType.USER_DEFINED)
        ns_cache[key] = ns
    return ns


def resolve(name):
    """Return (namespace, leaf). Falls back to a sanitized global label."""
    parts = split_ns(name)
    if len(parts) > 1 and all(len(p) > 0 for p in parts):
        try:
            parts = [clean(p) for p in parts]
            return get_ns(parts[:-1]), parts[-1]
        except Exception as e:
            pass
    return currentProgram.getGlobalNamespace(), sanitize(name)


def already_has(addr, ns, leaf):
    for s in symtab.getSymbols(addr):
        if s.getName() == leaf and s.getParentNamespace() == ns:
            return True
    return False


def apply_name(addr, name, primary):
    if DEFAULT_NAME.match(split_ns(name)[-1]) or SWITCH_NAME.search(name):
        return "skip_default"
    ns, leaf = resolve(name)
    if already_has(addr, ns, leaf):
        return "skip"
    func = getFunctionAt(addr)
    if func is None and primary and CREATE_MISSING_FUNCTIONS and mem.getBlock(addr).isExecute():
        func = createFunction(addr, None)
    if func is not None and primary and RENAME_EXISTING_FUNCTIONS:
        warn = False
        try:
            func.setParentNamespace(ns)
        except (Exception, Throwable) as e:
            warn = True
            println("WARN %s %s: setParentNamespace failed: %s" % (addr, name, str(e)[:100]))
        if func.getParentNamespace() == ns:
            try:
                func.setName(leaf, SourceType.USER_DEFINED)
            except (Exception, Throwable) as e:
                warn = True
                println("WARN %s %s: setName failed: %s" % (addr, name, str(e)[:100]))
            return "func_warn" if warn else "func"
        symtab.createLabel(addr, leaf, ns, SourceType.USER_DEFINED)
        return "label_fallback"
    symtab.createLabel(addr, leaf, ns, SourceType.USER_DEFINED)
    return "label"


def main():
    f = askFile("Select symbols CSV", "Open")
    by_addr = {}
    order = []
    with open(f.getAbsolutePath()) as fh:
        for row in csv.reader(fh):
            if len(row) < 2 or row[0].strip().lower() == "address":
                continue
            try:
                off = int(row[0], 16)
            except ValueError:
                continue
            a = BASE + off
            if a not in by_addr:
                by_addr[a] = []
                order.append(a)
            if row[1] not in by_addr[a]:
                by_addr[a].append(row[1])

    stats = {"func": 0, "func_warn": 0, "label": 0, "label_fallback": 0, "skip": 0, "skip_default": 0, "outside": 0, "error": 0}
    monitor.initialize(len(order))
    for a in order:
        monitor.checkCancelled()
        monitor.incrementProgress(1)
        addr = toAddr(a)
        if addr is None or not mem.contains(addr):
            stats["outside"] += 1
            continue
        for i, name in enumerate(by_addr[a]):
            try:
                stats[apply_name(addr, name, i == 0)] += 1
            except (Exception, Throwable) as e:
                stats["error"] += 1
                println("ERROR %s %s: %s" % (addr, name, e))

    println("done: %s" % stats)


main()
