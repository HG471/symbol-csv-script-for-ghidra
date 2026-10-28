# Export symbols (labels / functions, all sources) of the current Ghidra program to a CSV
#   "Address","Name","Last Updated","Last Updated User"
#@category Symbol

import csv
import os
import re
from ghidra.program.model.symbol import SourceType, SymbolType

BASE = 0x7100000000
# Which symbol sources to export. DEFAULT (auto-generated FUN_xxxx names) is left out.
INCLUDE_SOURCES = [SourceType.USER_DEFINED, SourceType.IMPORTED, SourceType.ANALYSIS]
# Ghidra auto-generated names (FUN_..., LAB_..., DAT_..., thunk_FUN_...): not real symbols.
DEFAULT_NAME = re.compile(r"^(thunk_)?(FUN|LAB|DAT|SUB|UNK|PTR|EXT|OFF|ADR)_[0-9A-Fa-f]{6,}$")
# Ghidra switch-table labels (switchD_7100000000::caseD_0, ::default, switchdataD_...).
SWITCH_NAME = re.compile(r"(^|::)(switchD|caseD|switchdataD)_[0-9A-Fa-f]+(::|$)")

# Handling of mangled names (starting with "_Z"):
#   "split" = readable names -> chosen file, mangled names -> <name>_mangled<ext>
#   "skip"  = do not export mangled names
#   "keep"  = everything in one file
MANGLED = "split"

symtab = currentProgram.getSymbolTable()
mem = currentProgram.getMemory()


def open_w(path):
    try:
        return open(path, "w", newline="")
    except TypeError:
        return open(path, "wb")


def write_csv(path, rows):
    fh = open_w(path)
    try:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writerow(["Address", "Name", "Last Updated", "Last Updated User"])
        for off, name in rows:
            w.writerow(["%08X" % off, name, "0", "0"])
    finally:
        fh.close()


def main():
    out = askFile("Save symbols CSV", "Save")

    rows = set()
    stat = {}          # (source, type) -> count, for every symbol seen
    skipped = {"default name": 0, "switch": 0, "wrong type": 0, "external": 0, "not in memory": 0, "below BASE": 0}
    for sym in symtab.getAllSymbols(False):
        key = "%s / %s" % (sym.getSource(), sym.getSymbolType())
        stat[key] = stat.get(key, 0) + 1
        if sym.getSource() not in INCLUDE_SOURCES:
            continue
        st = sym.getSymbolType()
        if st != SymbolType.LABEL and st != SymbolType.FUNCTION:
            skipped["wrong type"] += 1
            continue
        if sym.isExternal():
            skipped["external"] += 1
            continue
        addr = sym.getAddress()
        if not mem.contains(addr):
            skipped["not in memory"] += 1
            continue
        off = addr.getOffset() - BASE
        if off < 0:
            skipped["below BASE"] += 1
            continue
        if DEFAULT_NAME.match(sym.getName()):
            skipped["default name"] += 1
            continue
        name = sym.getName(True)  # includes namespace path with "::"
        if SWITCH_NAME.search(name):
            skipped["switch"] += 1
            continue
        rows.add((off, name))

    println("image base: %s (script BASE: 0x%X)" % (currentProgram.getImageBase(), BASE))
    println("symbols by source / type:")
    for k in sorted(stat):
        println("  %s: %d" % (k, stat[k]))
    println("skipped (after source filter): %s" % skipped)

    rows = sorted(rows)
    path = out.getAbsolutePath()

    if MANGLED == "keep":
        write_csv(path, rows)
        println("exported %d symbols to %s" % (len(rows), path))
        return

    plain = [r for r in rows if not r[1].startswith("_Z")]
    mangled = [r for r in rows if r[1].startswith("_Z")]
    write_csv(path, plain)
    println("exported %d symbols to %s" % (len(plain), path))

    if MANGLED == "split":
        root, ext = os.path.splitext(path)
        mpath = root + "_mangled" + ext
        write_csv(mpath, mangled)
        println("exported %d mangled symbols to %s" % (len(mangled), mpath))
    else:
        println("skipped %d mangled symbols" % len(mangled))


main()
