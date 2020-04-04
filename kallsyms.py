# Process vmlinux by kallsyms data

# Processes a vmlinux image based on the kallsyms data (assume there is no
# symbol map).  It will label all of the symbols, create entry points,
# functions, and disassemble

#@category  Linux

from ghidra.util.exception import CancelledException

# will ask for the following, attempting to just allow for 1 provided
# and script finds the rest, but not guarenteed
# unsigned long kallsyms_addresses[]
# int kallsyms_offsets[]
# u8 kallsyms_names[]
# unsigned long kallsyms_num_syms
# u8 kallsyms_token_table[]
# u16 kallsyms_token_index[]
# unsigned long kallsyms_markers[]


SIZEOF_PTR = currentProgram.getDefaultPointerSize()
PTR_MASK = (1 << (SIZEOF_PTR * 8)) - 1

def find_addresses_from_num_syms(num_syms):
    """Have kallsyms_num_syms, find kallsyms_addresses"""
    if num_syms is None:
        return None
    num_data = getInt(num_syms)
    addresses = num_syms.subtract(num_data * SIZEOF_PTR)
    return addresses

def find_num_syms_from_names(names):
    """Have kallsyms_names, find kallsyms_num_syms"""
    if names is None:
        return None
    num_syms = names
    while True:
        num_syms = num_syms.subtract(4)
        if getInt(num_syms):
            break
    return num_syms

def find_names_from_markers(markers):
    """Have kallsyms_markers, find kallsyms_names"""
    if markers is None:
        return None
    names = markers
    while True:
        names = names.previous()
        if getByte(names):
            break
    while True:
        if getShort(names) == 0:
            break
        names = names.previous()
    names = names.add(2)
    return names

def find_markers_from_token_table(token_table):
    """Have kallsyms_token_table, find kallsyms_markers"""
    if token_table is None:
        return None
    markers = token_table.subtract(4)
    while True:
        if getInt(markers):
            break
        markers = markers.subtract(4)
    while True:
        markers = markers.subtract(4)
        if getInt(markers) == 0:
            break
    return markers

def find_token_table_from_token_index(token_index):
    """Have kallsyms_token_index, find kallsyms_token_table"""
    if token_index is None:
        return None
    token_table = token_index
    while True:
        token_table = token_table.subtract(2)
        if getShort(token_table):
            break
    while True:
        if getShort(token_table.subtract(2)) == 0:
            break
        token_table = token_table.subtract(2)
    return token_table

def find_num_syms_from_addresses(addresses):
    """Have kallsyms_addresses, find kallsyms_num_syms"""
    if addresses is None:
        return None
    num_syms = addresses
    while True:
        if (getLong(num_syms) & PTR_MASK) == 0:
            break
        num_syms = num_syms.add(SIZEOF_PTR)
    num_syms = num_syms.subtract(SIZEOF_PTR)
    assert addresses == find_addresses_from_num_syms(num_syms), "Cannot validate addr/num"
    return num_syms

def find_names_from_num_syms(num_syms):
    """Have kallsyms_num_syms, find kallsyms_names"""
    if num_syms is None:
        return None
    names = num_syms.add(4)
    while True:
        if getByte(names) != 0:
            break
        names = names.next()
    assert num_syms == find_num_syms_from_names(names), "Cannot validate num/names"
    return names

def find_markers_from_names(names):
    """Have kallsyms_names, find kallsyms_markers"""
    if names is None:
        return None
    markers = names
    while True:
        if getShort(markers) == 0:
            break
        markers = markers.next()
    markers = markers.add(4 - (markers.getUnsignedOffset() & 3))
    while True:
        if getInt(markers.add(4)):
            break
        markers = markers.add(4)
    assert names == find_names_from_markers(markers), "Cannot validate names/markers"
    return markers

def find_token_table_from_markers(markers):
    """Have kallsyms_markers, find kallsyms_token_table"""
    if markers is None:
        return None
    token_table = markers.add(4)
    while True:
        if getInt(token_table) == 0:
            break
        token_table = token_table.add(4)
    while True:
        if getByte(token_table):
            break
        token_table = token_table.next()
    assert markers == find_markers_from_token_table(token_table), "Cannot validate markers/table"
    return token_table

def find_token_index_from_token_table(token_table):
    """Have kallsyms_token_table, find kallsyms_token_index"""
    if token_table is None:
        return None
    token_index = token_table.next()
    while True:
        if getShort(token_index) == 0:
            break
        token_index = token_index.next()
    token_index = token_index.add(4 - (token_index.getUnsignedOffset() & 3))
    while True:
        if getShort(token_index.add(2)):
            break
        token_index = token_index.add(2)
    assert token_table == find_token_table_from_token_index(token_index), "Cannot validate table/index"
    return token_index


try:
    kallsyms_addresses = askAddress("kallsyms_addresses",
                                    "Enter location of kallsyms_addresses")
except CancelledException:
    kallsyms_addresses = None

try:
    kallsyms_num_syms = askAddress("kallsyms_num_syms",
                                   "Enter location of kallsyms_num_syms")
except CancelledException:
    kallsyms_num_syms = None

try:
    kallsyms_names = askAddress("kallsyms_names",
                                "Enter location of kallsyms_names")
except CancelledException:
    kallsyms_names = None

try:
    kallsyms_markers = askAddress("kallsyms_markers",
                                  "Enter location of kallsyms_markers")
except CancelledException:
    kallsyms_markers = None

try:
    kallsyms_token_table = askAddress("kallsyms_token_table",
                                      "Enter location of kallsyms_token_table")
except CancelledException:
    kallsyms_token_table = None

try:
    kallsyms_token_index = askAddress("kallsyms_token_index",
                                      "Enter location of kallsyms_token_index")
except CancelledException:
    kallsyms_token_index = None


# This can be done with only one of these, its just about iterating through data
# have not seen any variance between this order in binaries

# start from the bottom and work up and then back down

if not kallsyms_token_table and kallsyms_token_index:
    kallsyms_token_table = find_token_table_from_token_index(kallsyms_token_index)
if not kallsyms_markers and kallsyms_token_table:
    kallsyms_markers = find_markers_from_token_table(kallsyms_token_table)
if not kallsyms_names and kallsyms_markers:
    kallsyms_names = find_names_from_markers(kallsyms_markers)
if not kallsyms_num_syms and kallsyms_names:
    kallsyms_num_syms = find_num_syms_from_names(kallsyms_names)
if not kallsyms_addresses and kallsyms_num_syms:
    kallsyms_addresses = find_addresses_from_num_syms(kallsyms_num_syms)
if not kallsyms_addresses:
    raise ValueError("Could not find enough info from inputs")
if kallsyms_addresses and not kallsyms_num_syms:
    kallsyms_num_syms = find_num_syms_from_addresses(kallsyms_addresses)
if kallsyms_num_syms and not kallsyms_names:
    kallsyms_names = find_names_from_num_syms(kallsyms_num_syms)
if kallsyms_names and not kallsyms_markers:
    kallsyms_markers = find_markers_from_names(kallsyms_names)
if kallsyms_markers and not kallsyms_token_table:
    kallsyms_token_table = find_token_table_from_markers(kallsyms_markers)
if kallsyms_token_table and not kallsyms_token_index:
    kallsyms_token_index = find_token_index_from_token_table(kallsyms_token_table)
if not kallsyms_token_index:
    raise ValueError("Could not find info")


assert not kallsyms_token_index is None
assert not kallsyms_token_table is None
assert not kallsyms_markers is None
assert not kallsyms_names is None
assert not kallsyms_num_syms is None
assert not kallsyms_addresses is None

if getSymbolAt(kallsyms_token_index) is None:
    createLabel(kallsyms_token_index, "kallsyms_token_index", True)
if getSymbolAt(kallsyms_token_table) is None:
    createLabel(kallsyms_token_table, "kallsyms_token_table", True)
if getSymbolAt(kallsyms_markers) is None:
    createLabel(kallsyms_markers, "kallsyms_markers", True)
if getSymbolAt(kallsyms_names) is None:
    createLabel(kallsyms_names, "kallsyms_names", True)
if getSymbolAt(kallsyms_num_syms) is None:
    createLabel(kallsyms_num_syms, "kallsyms_num_syms", True)
if getSymbolAt(kallsyms_addresses) is None:
    createLabel(kallsyms_addresses, "kallsyms_addresses", True)


def kallsyms_expand_symbol(offset):
    result = ""
    skipped_first = False
    data = kallsyms_names.add(offset)
    length = 0xff & getShort(data)
    if length < 0:
        print "wtf len"
        getMonitor().cancel()
        return offset, result
    data = data.next()
    offset += length + 1
    maxlen = 128
    while length > 0:
        if getMonitor().checkCanceled():
            return
        idx_idx = 0xff & getShort(data)
        if idx_idx < 0:
            print "wtf idx_idx"
            getMonitor().cancel()
            return offset, result
        idx = 0xffff & getInt(kallsyms_token_index.add(idx_idx << 1))
        if idx < 0:
            print "wtf IS"
            getMonitor().cancel()
            return offset, result
        tptr = kallsyms_token_table.add(idx)
        data = data.next()
        length -= 1
        while True:
            if getMonitor().checkCanceled():
                return offset, result
            tmp = 0xff & getShort(tptr)
            if tmp == 0:
                break
            if tmp < 0:
                print "wtf SB"
                getMonitor().cancel()
                return offset, result
            if skipped_first:
                if maxlen <= 1:
                    return offset, result
                result += chr(tmp)
                maxlen -= 1
            else:
                skipped_first = True
            tptr = tptr.next()
    return offset, result


off = 0
for i in range(getInt(kallsyms_num_syms)):
    if getMonitor().checkCanceled():
        break
    off, name = kallsyms_expand_symbol(off)
    if getMonitor().checkCanceled():
        break
    addr = PTR_MASK & getLong(kallsyms_addresses.add(i << 2))
    prev_addr = 0 if i == 0 else PTR_MASK & getLong(kallsyms_addresses.add((i-1) << 2))
    tmp_name = 0xff & getShort(kallsyms_names.add(off + 1))
    tmp_idx = 0xffff & getInt(kallsyms_token_index.add(tmp_name << 1))
    typ = chr(0xff & getShort(kallsyms_token_table.add(tmp_idx)))
    # print "%x %c %s" % (addr, typ, name)
    #ATTN  only handling 'T', 't', 'W', 'r', 'R', 'V', 's'
    if typ == 'T' or typ == 't':
        # the symbol is in the text (code) section
        createLabel(toAddr(addr), name, addr != prev_addr)
        addEntryPoint(toAddr(addr))
        createFunction(toAddr(addr), name)
        disassemble(toAddr(addr))
    elif typ == 'W' or typ == 'w':
        # weak symbol that has not been specifically tagged
        createLabel(toAddr(addr), name, False)
    elif typ == 'R' or typ == 'r':
        # the symbol is in a read only data section
        createLabel(toAddr(addr), name, addr != prev_addr)
    elif typ == 'V' or typ == 'v':
        # the symbol is a weak object
        createLabel(toAddr(addr), name, False)
    elif typ == 'S' or typ == 's':
        # the symbol is an unitialized/zero initialized data
        createLabel(toAddr(addr), name, addr != prev_addr)
    else:
        createLabel(toAddr(addr), name, addr != prev_addr)
