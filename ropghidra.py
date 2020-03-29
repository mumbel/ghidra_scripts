# Finds basic ROP gadgets by iterating functions' instructions

# This is a very basic approach to finding ROP gadgets by iterating
# each function and then iterate each instruction inside the function
# to find any instruction that contains a PCODE op that works for ROP
# while not containing other bad PCODE ops.  Each ROP gadget is just
# printed to console, probably want to sort/uniq/itemize them somehow

#@category    Search.InstructionPattern

from ghidra.program.model.pcode import PcodeOp

#TODO  what others?
# BRANCH
# BRANCHIND - want
# CALL
# CALLIND - want
# CALLOTHER
# RETURN - want
OPTYPE_BRANCHES = [PcodeOp.BRANCHIND]
OPTYPE_CALLS = [PcodeOp.CALLIND]
OPTYPE_RETURNS = [PcodeOp.RETURN]

#TOOD  avoiding these
AVOID_BRANCHES = [PcodeOp.CBRANCH]
AVOID_CALLS = [PcodeOp.CALL]

MAX_INSN_COUNT = 10

# Function
func = getFirstFunction()

while not func is None and not getMonitor().isCancelled():
    curr = getInstructionAt(func.getEntryPoint())
    while not curr is None and getFunctionContaining(curr.getAddress()) == func and not getMonitor().isCancelled():
        ops = curr.getPcode()
        if (any(_.getOpcode() in OPTYPE_BRANCHES+OPTYPE_CALLS+OPTYPE_RETURNS for _ in ops) and
                not any(_.getOpcode() in AVOID_BRANCHES+AVOID_CALLS for _ in ops)):
            insns = [curr]
            prev = curr.getPrevious()
            while (not prev is None and
                       getFunctionContaining(prev.getAddress()) == func and
                       len(insns) < MAX_INSN_COUNT and
                       not getMonitor().isCancelled() and
                       not any(_.getOpcode() in AVOID_BRANCHES+AVOID_CALLS for _ in prev.getPcode())):
                insns.insert(0, prev)
                prev = prev.getPrevious()
            print "%s : %s" % (insns[0].getAddress(), ' ; '.join(["%s" % _ for _ in insns]))
        curr = curr.getNext()
    func = getFunctionAfter(func)
