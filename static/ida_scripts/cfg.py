
class BasicBlock(object):

    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
        self.last_inst_addr = None
        self.last_inst = None
        self.preds = []
        self.succs = []


class Function(object):

    def __init__(self, addr, name):
        self.addr = addr
        self.name = name
        self.blocks = []
        self.callers = [] # (call_site, caller_addr)
        self.callees = [] # (call_site, callee_addr)


class CallGraph(object):

    def __init__(self):
        self.entry = None
        self.nodes = {}
        self.nodes_by_names = {}

    def get_node_by_name(self, name):
        return self.nodes_by_names.get(name)

    def get_node_by_addr(self, addr):
        for node in self.nodes.values():
            for block in node.blocks:
                if block.addr <= addr <= block.addr + block.size:
                    return node
        return None


class CFG(object):

    def __init__(self):
        self.entry = None
        self.nodes = {}

    def get_node_by_addr(self, addr):
        node = self.nodes.get(addr)
        if node:
            return node
        
        for node in self.nodes.values():
            if node.addr < addr and addr < node.addr + node.size:
                return node

        return None


