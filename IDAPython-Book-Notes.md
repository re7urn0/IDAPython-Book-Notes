# The Beginner’s Guide to IDAPython

- [The Beginner’s Guide to IDAPython](#the-beginners-guide-to-idapython)
  - [基础函数](#基础函数)
  - [段](#段)
  - [函数](#函数)
  - [指令](#指令)
  - [操作数](#操作数)
  - [基本块](#基本块)
  - [结构体](#结构体)
  - [枚举类型](#枚举类型)
  - [Xrefs](#xrefs)
  - [搜索](#搜索)
  - [选择数据](#选择数据)
  - [注释](#注释)
  - [重命名](#重命名)
  - [染色](#染色)
  - [访问原始数据](#访问原始数据)
  - [打补丁](#打补丁)
  - [输入和输出](#输入和输出)
  - [PyQt](#pyqt)
  - [生成批处理文件](#生成批处理文件)
  - [执行脚本](#执行脚本)
  - [Yara](#yara)
  - [Unicorn Engine](#unicorn-engine)


## 基础函数
```python
# .text:004974C2                 mov     esi, ecx

# 返回当前光标位置
Python>ea = idc.get_screen_ea()
Python>ea = here()
Python>print("0x%x %s" % (ea, ea))
0x4974c2 4814018
```
```python
# idb起始/结束地址
Python>print("0x%x" % idc.get_inf_attr(INF_MIN_EA))
0x401000
Python>print("0x%x" % idc.get_inf_attr(INF_MAX_EA))
0x523000
```
```python
# 返回当前地址的指定内容
Python>idc.get_segm_name(ea) # get text
'.text'
Python>idc.generate_disasm_line(ea, 0) # get disassembly
'mov     esi, ecx'
Python>idc.print_insn_mnem(ea) # get mnemonic
'mov'
Python>idc.print_operand(ea,0) # get first operand
'esi'
Python>idc.print_operand(ea,1) # get second operand
'ecx'
```
```python
# 地址是否无效
Python>idaapi.BADADDR # 返回内置无效地址
0xffffffff
Python>if BADADDR != here(): print("valid address")
valid address
```

## 段
```python
# 遍历所有段
Python>import idautils
Python>for seg in idautils.Segments(): \
        print("%s, 0x%x, 0x%x" % (idc.get_segm_name(seg), idc.get_segm_start(seg),idc.get_segm_end(seg)))
.text, 0x401000, 0x4c4000
.idata, 0x4c4000, 0x4c4990
.rdata, 0x4c4990, 0x4f8000
.data, 0x4f8000, 0x523000
```
```python
# 返回下一个段起始地址
Python>seg = idc.get_next_seg(ea) # 参数: 当前段任意地址
Python>print("%s, 0x%x" % (idc.get_segm_name(seg), seg))
.idata, 0x4c4000
```
```python
# 通过段名，返回段起始地址
Python>idc.get_segm_by_sel(idc.selector_by_name('.text'))
0x401000    # .text
Python>idc.get_segm_by_sel(idc.selector_by_name('.text') + 1)
0x4c4990    # .idata
```

## 函数
```python
# 遍历所有函数
Python>for func in idautils.Functions(): 
        print("0x%x, %s" % (func, idc.get_func_name(func)))
0x401000, sub_401000
0x401063, sub_401063
0x401149, sub_401149
...
0x4c3f54, sub_4C3F54
0x4c3f5e, sub_4C3F5E
```
```python
# 遍历区域内所有函数
Python>for func in idautils.Functions(0x401000,0x402000): 
        print("0x%x, %s" % (func, idc.get_func_name(func)))
0x401000, sub_401000
0x401063, sub_401063
...
0x401fb0, sub_401FB0
0x401fe0, sub_401FE0
```
```python
# 返回当前函数边界
Python>func = idaapi.get_func(ea)
Python>print("Start: 0x%x, End: 0x%x" % (func.start_ea, func.end_ea))
Start: 0x4974bb, End: 0x4974d6
```
```python
# 查看函数类对象的导出函数和属性
Python>type(func)
<class 'ida_funcs.func_t'>
Python>dir(func)
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__get_points__', '__get_referers__', '__get_regargs__', '__get_regvars__', '__get_tails__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__swig_destroy__', '__weakref__', '_print', 'addresses', 'analyzed_sp', 'argsize', 'clear', 'code_items', 'color', 'compare', 'contains', 'data_items', 'does_return', 'empty', 'endEA', 'end_ea', 'extend', 'flags', 'fpd', 'frame', 'frregs', 'frsize', 'head_items', 'intersect', 'is_far', 'need_prolog_analysis', 'not_tails', 'overlaps', 'owner', 'pntqty', 'points', 'referers', 'refqty', 'regargqty', 'regargs', 'regvarqty', 'regvars', 'size', 'startEA', 'start_ea', 'tailqty', 'tails', 'this', 'thisown']
```
```python
# 返回上一个/下一个函数起始地址
Python>idc.get_prev_func(ea)
0x4974a6
Python>idc.get_next_func(ea)
0x4974d6
```
```python
# idc.get_func_attr(), 返回函数边界值; 反汇编函数.
# bug: 函数存在大跳转时会异常退出, 应使用 idautils.FuncItems(ea)
Python>ea = here()
Python>start = idc.get_func_attr(ea, FUNCATTR_START)
Python>end = idc.get_func_attr(ea, FUNCATTR_END)
Python>cur_addr = start
Python>while cur_addr <= end:
	print("0x%x %s" % (cur_addr, idc.generate_disasm_line(cur_addr, 0))) # 当前地址反汇编代码
	cur_addr = idc.next_head(cur_addr, end) # 返回下一条指令起始地址
Python>
0x4974bb push    ebp
0x4974bc mov     ebp, esp
0x4974be push    esi
0x4974bf push    [ebp+arg_0]
0x4974c2 mov     esi, ecx
0x4974c4 call    sub_43C960
0x4974c9 mov     dword ptr [esi], offset
0x4974cf mov     eax, esi
0x4974d1 pop     esi
0x4974d2 pop     ebp
0x4974d3 retn    4
```
```python
# 遍历函数，返回函数类型
Python>for func in idautils.Functions():
        flags = idc.get_func_attr(func,FUNCATTR_FLAGS)
        if flags & FUNC_NORET:  # 标识没有返回值的函数
                print("0x%x FUNC_NORET" % func)
        if flags & FUNC_FAR:    # 标识使用内存段的函数
                print("0x%x FUNC_FAR" % func)
        if flags & FUNC_LIB:    # 标志用于标记动态链接库的函数
                print("0x%x FUNC_LIB" % func)
        if flags & FUNC_STATIC: # 标志用于标记 static 函数
                print("0x%x FUNC_STATIC" % func)
        if flags & FUNC_FRAME:  # 标志用于标示使用了 ebp 作为栈帧的函数
                print("0x%x FUNC_FRAME" % func)
        if flags & FUNC_USERFAR: # 标识用户已指定函数的距离
                print("0x%x FUNC_USERFAR" % func)
        if flags & FUNC_HIDDEN: # 标识函数是隐藏的，需要展开才能查看
                print("0x%x FUNC_HIDDEN" % func)
        if flags & FUNC_THUNK: # 标志用于标示中转函数，即只用一个 jmp 的函数
                print("0x%x FUNC_THUNK" % func)
        if flags & FUNC_BOTTOMBP: # 标识基指针指向堆栈指针的函数
                print("0x%x FUNC_BOTTOMBP" % func)
0x401000 FUNC_FRAME
0x401063 FUNC_FRAME
...
0x4c3ca0 FUNC_HIDDEN
0x4c3d60 FUNC_FRAME
0x4c3e90 FUNC_FRAME
```
```python
# 定义函数
Python>idc.add_func(0x00407DC1, 0x00407E90)
```
```python
# 函数参数
Python>idaapi.get_arg_addrs(ea)
[0x493a52, 0x493a4d, 0x493a48, 0x493a46]
```

## 指令
```python
#返回当前函数所有指令
Python>dism_addr = list(idautils.FuncItems(here()))
Python>for line in dism_addr: 
        print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
0x43f900 push    ebp
0x43f901 mov     ebp, esp
0x43f903 push    [ebp+dwBytes]; dwBytes
0x43f906 push    0; dwFlags
0x43f908 push    dword ptr [ecx+4]; hHeap
0x43f90b call    ds:HeapAlloc
0x43f911 pop     ebp
0x43f912 retn    4
```
```python
# 返回所有的动态调用指令(例: call eax; jmp edi)
Python>
for func in idautils.Functions():
        flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
        dism_addr = list(idautils.FuncItems(func))
        for line in dism_addr:
                m = idc.print_insn_mnem(line)   # get mnemonic
                if m == 'call' or m == 'jmp':
                        op = idc.get_operand_type(line, 0)
                        if op == o_reg:
                                 print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
Python>
0x401196 call    esi ; LoadLibraryA
0x4011ac call    esi ; LoadLibraryA
0x4011eb call    eax ; dword_521588
0x404619 call    ebx ; SysStringLen
...
```
```python
# 上一条/下一条指令
Python>ea = here()
Python>next_instr = idc.next_head(ea)
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(next_instr, 0)))
0x4011ac mov     ecx, eax
Python>prev_instr = idc.prev_head(ea)
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(prev_instr, 0)))
0x4011ac push    offset LibFileName; "hhctrl.ocx"
```
```python
# 返回所有的动态调用指令，使用 idaapi.decode_insn(insn_t, ea) 函数
Python>JMPS = [idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni]
Python>CALLS = [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]
Python>
for func in idautils.Functions():
        flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
        dism_addr = list(idautils.FuncItems(func))
        for line in dism_addr:
                ins = ida_ua.insn_t()
                idaapi.decode_insn(ins, line)
                if ins.itype in CALLS or ins.itype in JMPS:
                        if ins.Op1.type == o_reg:
                                print("0x%x %s" % (line, idc.generate_disasm_line(line, 0)))
Python>
0x401196 call    esi ; LoadLibraryA
0x4011ac call    esi ; LoadLibraryA
0x4011eb call    eax ; dword_521588
0x404619 call    ebx ; SysStringLen
...
```
```python
# 指令的属性 ida_ua.insn_t()
Python>dir(ins)
['Op1', 'Op2', 'Op3', 'Op4', 'Op5', 'Op6', 'Op7', 'Op8', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__get_auxpref__', '__get_operand__', '__get_ops__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__set_auxpref__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__swig_destroy__', '__weakref__', 'add_cref', 'add_dref', 'add_off_drefs', 'assign', 'auxpref', 'auxpref_u16', 'auxpref_u8', 'create_op_data', 'create_stkvar', 'cs', 'ea', 'flags', 'get_canon_feature', 'get_canon_mnem', 'get_next_byte', 'get_next_dword', 'get_next_qword', 'get_next_word', 'insnpref', 'ip', 'is_64bit', 'is_canon_insn', 'is_macro', 'itype', 'ops', 'segpref', 'size', 'this', 'thisown']
```

## 操作数
```python
# o_void 指令没有操作数，返回 0
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x401223 retn
Python>print(idc.get_operand_type(ea,0))
0
```
```python
# o_reg 操作数为寄存器，返回 1
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x401222 pop     ecx
Python>print(idc.get_operand_type(ea,0))
1
```
```python
# o_mem 操作数为直接内存引用，返回 2
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x4012b9 mov     dword_501D38, eax
Python>print(idc.get_operand_type(ea,0))
2
```
```python
# o_phrase 操作数由基址寄存器和/或索引寄存器组成，返回 3
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x4015aa mov     [edi+ecx], eax
Python>print(idc.get_operand_type(ea,0))
3
```
```python
# o_displ 操作数由寄存器和偏移量组成，返回 4
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x40168d mov     [ebp+var_28], offset sub_433640
Python>print(idc.get_operand_type(ea,0))
4
```
```python
# o_imm 操作数为一个值，返回 5
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x401694 push    7F00h
Python>print(idc.get_operand_type(ea,0))
5
```
```python
# o_far 此操作数在x86或x86_64中不常见, 用于查找正在访问直接远地址的操作数
#       内部表示为6
```
```python
# o_near 此操作数在x86或x86_64中不常见, 用于查找正在访问直接邻近地址的操作数
#        内部表示为7
```
```python
# 将操作数从数值转化为字符串
min = idc.get_inf_attr(INF_MIN_EA)
max = idc.get_inf_attr(INF_MAX_EA)
# for each known function
for func in idautils.Functions():
        flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
        # skip library & thunk functions
        if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
        dism_addr = list(idautils.FuncItems(func))
        for curr_addr in dism_addr:
                if idc.get_operand_type(curr_addr, 0) == 5 and (min < idc.get_operand_value(curr_addr, 0) < max):
                        idc.op_plain_offset(curr_addr, 0, 0)
                if idc.get_operand_type(curr_addr, 1) == 5 and (min < idc.get_operand_value(curr_addr, 1) < max):
                        idc.op_plain_offset(curr_addr, 1, 0)
```

## 基本块
```python
# 基本块是没有分支的直线代码序列，由单入口点和单出口点组成
.text:00401034 push esi
.text:00401035 push edi
.text:00401036 push 0Ah ; Size
.text:00401038 call ds:malloc
.text:0040103E mov esi, eax
.text:00401040 mov edi, offset str_encrypted
.text:00401045 xor eax, eax ; eax = 0
.text:00401047 sub edi, esi
.text:00401049 pop ecx
.text:0040104A
.text:0040104A loop: ; CODE XREF: _main+28↓j
.text:0040104A lea edx, [eax+esi]
.text:0040104D mov cl, [edi+edx]
.text:00401050 xor cl, ds:b_key ; cl = 0
.text:00401056 inc eax
.text:00401057 mov [edx], cl
.text:00401059 cmp eax, 9 ; index
.text:0040105C jb short loop
.text:0040105E push esi
.text:0040105F push offset str_format
.text:00401064 mov byte ptr [esi+9], 0
.text:00401068 call w_vfprintf
.text:0040106D push esi ; Memory
.text:0040106E call ds:free
.text:00401074 add esp, 0Ch
.text:00401077 xor eax, eax ; eax = 0
.text:00401079 pop edi
.text:0040107A pop esi
.text:0040107B retn
.text:0040107B _main endp
```

```python

# 获取发生异或的基本块（位于0x0401050）
ea = 0x0401050
f = idaapi.get_func(ea)
fc = idaapi.FlowChart(f, flags=idaapi.FC_PREDS) # FlowChart 对象可以遍历所有块
for block in fc:
        print("ID: %i Start: 0x%x End: 0x%x" % (block.id, block.start_ea, block.end_ea))
        if block.start_ea <= ea < block.end_ea:
                print(" Basic Block selected")

        successor = block.succs() # returns a generator which contains all the successor address
        for addr in successor:
                print(" Successor: 0x%x" % addr.start_ea)
        pre = block.preds() #  returns a generator which contains all the predecessor addresses
        for addr in pre:
                print(" Predecessor: 0x%x" % addr.end_ea)
        if ida_gdl.is_ret_block(block.type):
                print(" Return Block")

ID: 0 Start: 0x401034 End: 0x40104a
 Successor: 0x40104a
ID: 1 Start: 0x40104a End: 0x40105e
 Basic Block selected
 Successor: 0x40105e
 Successor: 0x40104a
 Predecessor: 0x40104a
 Predecessor: 0x40105e
ID: 2 Start: 0x40105e End: 0x40107c
 Predecessor: 0x40105e
 Return Block
```

## 结构体
```python
# seg000:00000000 xor ecx, ecx
# seg000:00000002 mov eax, fs:[ecx+30h]
# seg000:00000006 mov eax, [eax+0Ch]
# seg000:00000009 mov eax, [eax+14h]

# 将 offset 标记为结构体名称
status = idc.add_default_til("ntapi")     # load the type library(TIL)
if status:
        idc.import_type(-1, "_TEB")       # type added to the end of IDA’s imported types list
        idc.import_type(-1, "PEB")
        idc.import_type(-1, "PEB_LDR_DATA")

        ea = 2                            # the offset that is going to be labeled
        teb_id = idc.get_struc_id("_TEB") # get the id of imported type
        idc.op_stroff(ea, 1, teb_id, 0)   # add the structure names "_TEB" to the offsets

        ea = idc.next_head(ea)
        peb_id = idc.get_struc_id("PEB") 
        idc.op_stroff(ea, 1, peb_id, 0)   # "PEB"

        ea = idc.next_head(ea)
        peb_ldr_id = idc.get_struc_id("PEB_LDR_DATA") 
        idc.op_stroff(ea, 1, peb_ldr_id, 0) # "PEB_LDR_DATA"
```
```python
# 创建结构体

"""
0:000> dt nt!_PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
 +0x000 Length : Uint4B
 +0x004 Initialized : UChar
 +0x008 SsHandle : Ptr64 Void
 +0x010 InLoadOrderModuleList : _LIST_ENTRY
 +0x020 InMemoryOrderModuleList : _LIST_ENTRY
 +0x030 InInitializationOrderModuleList : _LIST_ENTRY
 +0x040 EntryInProgress : Ptr64 Void
 +0x048 ShutdownInProgress : UChar
 +0x050 ShutdownThreadId : Ptr64 Void
"""

sid = idc.get_struc_id("my_peb_ldr_data") # 返回结构体 id
if sid != idc.BADADDR:
        idc.del_struc(sid)
sid = idc.add_struc(-1, "my_peb_ldr_data", 0) # 创建结构体
# idc.add_struc_member(sid, name, offset, flag, typeid, nbytes)
idc.add_struc_member(sid, "length", 0, idc.FF_DWORD, -1, 4) # 添加结构体成员
idc.add_struc_member(sid, "initialized", 4, idc.FF_DWORD, -1, 4)
idc.add_struc_member(sid, "ss_handle", -1, idc.FF_WORD, -1, 2)
idc.add_struc_member(sid, "in_load_order_module_list", -1, idc.FF_DATA, -1, 10)
idc.add_struc_member(sid, "in_memory_order_module_list", -1, idc.FF_QWORD +
idc.FF_WORD, -1, 10)
idc.add_struc_member(sid, "in_initialization_order_module_list", -1, idc.FF_QWORD +
idc.FF_WORD, -1, 10)
idc.add_struc_member(sid, "entry_in_progress", -1, idc.FF_QWORD, -1, 8)
idc.add_struc_member(sid, "shutdown_in_progress", -1, idc.FF_WORD, -1, 2)
idc.add_struc_member(sid, "shutdown_thread_id", -1, idc.FF_QWORD, -1, 8)

"""
# IDA 结构体窗口显示
00000000 my_peb_ldr_data struc ; (sizeof=0x3A, mappedto_139)
00000000 length dd ?
00000004 initialized dd ?
00000008 ss_handle dw ?
0000000A in_load_order_module_list db 10 dup(?)
00000014 in_memory_order_module_list dt ?
0000001E in_initialization_order_module_list dt ?
00000028 entry_in_progress dq ?
00000030 shutdown_in_progress dw ?
"""
```

## 枚举类型
```python
# 实现 z0mbie hash
import pefile

def ror32(val, amt):
        return ((val >> amt) & 0xffffffff) | ((val << (32 - amt)) & 0xffffffff)

def add32(val, amt):
        return (val + amt) & 0xffffffff

def z0mbie_hash(name):
        hash = 0
        for char in name:
                hash = add32(ror32(hash, 13), ord(char) & 0xff)
        return hash

def get_name_from_hash(file_name, hash):
        pe = pefile.PE(file_name)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if z0mbie_hash(exp.name) == hash:
                        return exp.name

api_name = get_name_from_hash("kernel32.dll", 0xCA2BD06B)
# 添加枚举类型
if api_name:
        id = idc.add_enum(-1, "z0mbie_hashes", idaapi.hexflag())
        idc.add_enum_member(id, api_name, 0xCA2BD06B, -1)

# 执行代码后，在值所在位置，按"M"快捷键添加枚举类型
```

## Xrefs
```python
# 定位所有调用 "WriteFile" 函数的地址(xrefs_to)
# 动态导入且手动重命名的API，不会显示为代码交叉引用
Python>wf_addr = idc.get_name_ea_simple("WriteFile") # returns the address of the API
Python>print("0x%x %s" % (wf_addr, idc.generate_disasm_line(wf_addr, 0)))
0x4c425c extrn WriteFile:dword
Python>for addr in idautils.CodeRefsTo(wf_addr, 0): 
        print("0x%x %s" % (addr, idc.generate_disasm_line(addr, 0)))
0x408d3f call    ds:WriteFile
0x4af9b5 call    ds:WriteFile
0x4af9ee call    ds:WriteFile
0x4afbc9 call    ds:WriteFile
0x4afcb7 call    ds:WriteFile
0x4afddc call    ds:WriteFile
0x4b0085 call    ds:WriteFile
```
```python
# 被调用的函数的地址(xrefs_from)
Python>ea = 0x408d3f
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x408d3f call    ds:WriteFile
Python>for addr in idautils.CodeRefsFrom(ea, 0): 
        print("0x%x %s" % (addr, idc.generate_disasm_line(addr, 0)))
0x4c425c extrn WriteFile:dword
```
```python
# 数据的交叉引用(DataRefsTo)
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x4dad58 db 'ZwQueryWnfStateData',0
Python>for addr in idautils.DataRefsTo(ea): 
        print("0x%x %s" % (addr, idc.generate_disasm_line(addr, 0)))
0x47219e push    offset aZwquerywnfstat; "ZwQueryWnfStateData"

# DataRefsFrom
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x47219e push    offset aZwquerywnfstat; "ZwQueryWnfStateData"
Python>for addr in idautils.DataRefsFrom(ea): 
        print("0x%x %s" % (addr, idc.generate_disasm_line(addr, 0)))
0x4dad58 db 'ZwQueryWnfStateData',0
```
```python
# 显示所有的交叉引用(XrefsTo)
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x1000eee0 unicode 0, <Path>,0
Python>for xref in idautils.XrefsTo(ea, 1): # type"1"表示"Data_Offset", idautils.XrefTypeName(xref.type)
        print("%i %s 0x%x 0x%x %i" % (xref.type, idautils.XrefTypeName(xref.type),xref.frm, xref.to, xref.iscode))
Python>
1 Data_Offset 0x1000ac0d 0x1000eee0 0
Python>print("0x%x %s" % (xref.frm, idc.generate_disasm_line(xref.frm, 0))
0x1000ac0d push offset KeyName ; "Path"
```
```python
# 显示任何的交叉引用(XrefsTo)
"""
.text:1000AAF6 jnb short loc_1000AB02 ; XREF
.text:1000AAF8 mov eax, [ebx+0Ch]
.text:1000AAFB mov ecx, [esi]
.text:1000AAFD sub eax, edi
.text:1000AAFF mov [edi+ecx], eax
.text:1000AB02
.text:1000AB02 loc_1000AB02: ; ea is here()
.text:1000AB02 mov byte ptr [ebx], 1
"""
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x1000ab02 mov byte ptr [ebx], 1
Python>for xref in idautils.XrefsTo(ea, 1): # flag = 1
        print("%i %s 0x%x 0x%x %i" % (xref.type, idautils.XrefTypeName(xref.type),xref.frm, xref.to, xref.iscode))
Python>
19 Code_Near_Jump 0x1000aaf6 0x1000ab02 1
Python>for xref in idautils.XrefsTo(ea, 0): # flag = 0
        print("%i %s 0x%x 0x%x %i" % (xref.type, idautils.XrefTypeName(xref.type),xref.frm, xref.to, xref.iscode))
Python>
21 Ordinary_Flow 0x1000aaff 0x1000ab02 1
19 Code_Near_Jump 0x1000aaf6 0x1000ab02 1
```
```python
# 精简交叉引用的所有地址
def get_to_xrefs(ea):
        xref_set = set([])
        for xref in idautils.XrefsTo(ea, 1):
        xref_set.add(xref.frm)
        return xref_set

def get_frm_xrefs(ea):
        xref_set = set([])
        for xref in idautils.XrefsFrom(ea, 1):
        xref_set.add(xref.to)
        return xref_set

Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0xa21138 extrn GetProcessHeap:dword
Python>get_to_xrefs(ea)
set([10568624, 10599195])
Python>[("0x%x" % x) for x in get_to_xrefs(ea)]
['0xa143b0', '0xa1bb1b']
```

## 搜索
```python
# 查找字节或二进制模式 ida_search.find_binary(start, end, searchstr,radiux,sflag)
"""
sflag:
        SEARCH_UP = 0
        SEARCH_DOWN = 1
        SEARCH_NEXT = 2
        SEARCH_CASE = 4
        SEARCH_REGEX = 8
        SEARCH_NOBRK = 16
        SEARCH_NOSHOW = 32
        SEARCH_IDENT = 128
        SEARCH_BRK = 256
"""
pattern = '55 8B EC'
addr = idc.get_inf_attr(INF_MIN_EA)
for x in range(0, 5):
        addr = ida_search.find_binary(addr, idc.BADADDR, pattern,16,ida_search.SEARCH_NEXT|ida_search.SEARCH_DOWN)
        if addr != idc.BADADDR:
                print("0x%x %s" % (addr, idc.generate_disasm_line(addr, 0)))
Python>
0x401002 push    ebp
0x401065 push    ebp
0x40114b push    ebp
0x401320 push    ebp
0x4013f0 push    ebp
```
```python
# 查找字符串 ida_search.find_text(ea, y, x, searchstr, sflag)
cur_addr = idc.get_inf_attr(INF_MIN_EA)
for x in range(0, 5):
        cur_addr = ida_search.find_text(cur_addr, 0, 0, "message",ida_search.SEARCH_DOWN)
        if addr == idc.BADADDR:
                break
        print("0x%x %s" % (cur_addr, idc.generate_disasm_line(cur_addr, 0)))
        cur_addr = idc.next_head(cur_addr)
Python>
0x408cb0 push    ebp
0x408cc4 push    [ebp+dwMessageId]; dwMessageId
0x408cce call    ds:FormatMessageA
0x408fa1 call    ds:MessageBoxW
0x409487 call    ds:MessageBoxW
```
```python
# 判定地址类型
idc.is_code(f) # f = idc.get_full_flags(ea)

idc.is_data(f)

idc.is_head(f) # Returns True if IDA has marked the address as head

idc.is_tail(f)

idc.is_unknown(f) # IDA has not identified if the address is code or data

Python>idc.is_code(idc.get_full_flags(ea))
True
```
```python
# 查找下一条类型指令
ida_search.find_code(ea, sflag)

ida_search.find_data(ea, sflag)

ida_search.find_unknown(ea, flag)

ida_search.find_defined(ea, flag) # find an address that IDA identified as code or data

ida_search.find_imm(ea, flag, value) # 查找特定值

Python>addr = ida_search.find_imm(get_inf_attr(INF_MIN_EA), SEARCH_DOWN, 0x343FD)
Python>addr
[268453092, 0] # return [address, operand]
Python>print("0x%x %s %x" % (addr[0], idc.generate_disasm_line(addr[0], 0),addr[1]))
0x100044e4 imul eax, 343FDh 0
```
```python
# 查找特定值
addr = idc.get_inf_attr(INF_MIN_EA)
while True:
        addr, operand = ida_search.find_imm(addr, SEARCH_DOWN | SEARCH_NEXT, 0x7A)
        if addr == BADADDR:
                break
        print("0x%x %s Operand %i" % (addr, idc.generate_disasm_line(addr, 0),operand))
Python>
0x41085c mov     [ebp+var_4], 7Ah ; 'z' Operand 1
0x41d429 cmp     eax, 7Ah ; 'z' Operand 1
...
0x4ff9aa db  7Ah ; z Operand 0
0x4ffbc3 db  7Ah ; z Operand 0
```

## 选择数据
```python
"""
# 光标选中的数据
.text:00401063                 mov     edi, edi
.text:00401065                 push    ebp
.text:00401066                 mov     ebp, esp
.text:00401068                 sub     esp, 118h
.text:0040106E                 mov     eax, ___security_cookie
.text:00401073                 xor     eax, ebp
.text:00401075                 mov     [ebp+var_4], eax
.text:00401078                 mov     eax, [ebp+arg_0]
.text:0040107B                 push    esi
"""
Python>start = idc.read_selection_start()
Python>print("0x%x" % start)
0x401063
Python>end = idc.read_selection_end() # 返回下个地址的开始位置
Python>print("0x%x" % end)
0x40107c
```

## 注释
```python
# 常规注释
idc.set_cmt(ea, comment,0)

# 可重复注释
idc.set_cmt(ea, comment, 1)
```
```python
# XOR 清零寄存器或值时添加注释
for func in idautils.Functions():                       # loop through all functions
        flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
        # skip library & thunk functions
        if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
        dism_addr = list(idautils.FuncItems(func))      # loop through all the instructions 
        for ea in dism_addr:
                if idc.print_insn_mnem(ea) == "xor":
                        if idc.print_operand(ea, 0) == idc.print_operand(ea, 1):
                                comment = "%s = 0" % (idc.print_operand(ea, 0))
                                idc.set_cmt(ea, comment, 0)

0040B0F7 xor al, al ; al = 0
0040B0F9 jmp short loc_40B163
```
```python
# 获取注释 (repeatable comment: True or False)
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x40b0f7 xor al, al ; al = 0
Python>idc.get_cmt(ea, False)
al = 0
```
```python
# 函数注释 (repeatable comment: True(1) or False(0) )
idc.set_func_cmt(ea, cmt, repeatable)
idc.get_func_cmt(ea, repeatable)

Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x401040 push ebp
Python>idc.get_func_name(ea)
sub_401040
Python>idc.set_func_cmt(ea, "check out later", 1)
True

"""
00401C07 push ecx
00401C08 call sub_401040 ; check out later
00401C0D add esp, 4
"""
```

## 重命名
```python
# 函数重命名
idc.set_name(ea, name, SN_CHECK)

Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x10005b3e push ebp
Python>idc.set_name(ea, "w_HeapAlloc", SN_CHECK)
True
Python>idc.get_func_name(ea)
w_HeapAlloc
"""
10005B3E w_HeapAlloc proc near
10005B3E
10005B3E dwBytes = dword ptr 8
10005B3E
10005B3E push ebp
10005B3F mov ebp, esp
10005B41 push [ebp+dwBytes] ; dwBytes
10005B44 push 8 ; dwFlags
10005B46 push hHeap ; hHeap
10005B4C call ds:HeapAlloc
10005B52 pop ebp
10005B53 retn
10005B53 w_HeapAlloc endp
"""
```
```python
# 操作数重命名
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x4047b0 mov eax, dword_41400C
Python>op = idc.get_operand_value(ea, 1)
Python>idc.set_name(op, "BETA", SN_CHECK)
True
Python>print("0x%x %s" % (ea, idc.generate_disasm_line(ea, 0)))
0x4047b0 mov eax, BETA[esi]
```
```python
# 地址是否被用户重命名 (by address’s flags)
Python>idc.hasUserName(ida_bytes.get_flags(here()))
True
```

## 染色
```python
# idc.set_color(ea, what, color)  what:  CIC_ITEM |  CIC_FUNC |  CIC_SEGM

# 给所有包含call指令的函数染色
for func in idautils.Functions():
        flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
        # skip library & thunk functions
        if flags & FUNC_LIB or flags & FUNC_THUNK:
                continue
        dism_addr = list(idautils.FuncItems(func))
        for ea in dism_addr:
        if idc.print_insn_mnem(ea) == "call":
                idc.set_color(ea, CIC_ITEM, 0xDFD9F3)
```
```python
Python>"0x%x" % (idc.get_color(0x0401469, CIC_ITEM))
0xdfd9f3
Python>"0x%x" % (idc.get_color(0x0401469, CIC_FUNC))
0xffffffff
Python>"0x%x" % (idc.get_color(0x0401469, CIC_SEGM))
0xffffffff
```

## 访问原始数据
```python
# 访问原始数据API
idc.get_wide_byte(ea)
idc.get_wide_word(ea)
idc.get_wide_dword(ea)
idc.get_qword(ea)
idc.GetFloat(ea)
idc.GetDouble(ea)

"""
00A14380 8B 0D 0C 6D A2 00 mov ecx, hHeap
00A14386 50 push eax
00A14387 6A 08 push 8
"""
Python>"0x%x" % idc.get_wide_byte(ea)
0x8b
Python>"0x%x" % idc.get_wide_word(ea)
0xd8b
Python>"0x%x" % idc.get_wide_dword(ea)
0x6d0c0d8b
Python>"0x%x" % idc.get_qword(ea)
0x6a5000a26d0c0d8bL
Python>idc.GetFloat(ea) # Example not a float value
2.70901711372e+27
Python>idc.GetDouble(ea)
1.25430839165e+204
```
```python
# 获取指定大小的字节
Python>for byte in idc.get_bytes(ea, 6):
        print("0x%X" % byte),
0x8B 0xD 0xC 0x6D 0xA2 0x0
```

## 打补丁
```python
# 用值修补地址
idc.patch_byte(ea, value)
idc.patch_word(ea, value)
idc.patch_dword(ea, value)

"""
# 加密数据
.data:1001ED3C aGcquEUdg_bUfuD db 'gcqu^E]~UDG_B[uFU^DC',0
.data:1001ED51 align 8
.data:1001ED58 aGcqs_cuufuD db 'gcqs\_CUuFU^D',0
.data:1001ED66 align 4
.data:1001ED68 aWud@uubQU db 'WUD@UUB^Q]U',0
.data:1001ED74 align 8

# 解密函数
100012A0 push esi
100012A1 mov esi, [esp+4+_size]
100012A5 xor eax, eax
100012A7 test esi, esi
100012A9 jle short _ret
100012AB mov dl, [esp+4+_key] ; assign key
100012AF mov ecx, [esp+4+_string]
100012B3 push ebx
100012B4
100012B4 _loop: ;
100012B4 mov bl, [eax+ecx]
100012B7 xor bl, dl ; data ^ key
100012B9 mov [eax+ecx], bl ; save off byte
100012BC inc eax ; index/count
100012BD cmp eax, esi
100012BF jl short _loop
100012C1 pop ebx
100012C2
100012C2 _ret: ;
100012C2 pop esi
100012C3 retn
"""
# patch_byte() 实现 XOR 解密
Python>start = idc.read_selection_start()
Python>end = idc.read_selection_end()
Python>print hex(start)
0x1001ed3c
Python>print hex(end)
0x1001ed50
Python>def xor(size, key, buff):
        for index in range(0, size):
                cur_addr = buff + index
                temp = idc.get_wide_byte(cur_addr ) ^ key
                idc.patch_byte(cur_addr, temp)
Python>
Python>xor(end - start, 0x30, start)
Python>idc.get_strlit_contents(start)
WSAEnumNetworkEvents
```

## 输入和输出
```python
"""
# 导入/保存文件
ida_kernwin.ask_file(forsave, mask, prompt)
        forsave: 0, 打开对话框; 1, 保存对话框
        mask: 文件扩展, 例如 "*.dll"
        prompt: 窗口标题
"""

import sys
import idaapi

class IO_DATA():
        def __init__(self):
                self.start = idc.read_selection_start()
                self.end = idc.read_selection_end()
                self.buffer = ''
                self.ogLen = None
                self.status = True
                self.run()

        def checkBounds(self):
                if self.start is BADADDR or self.end is BADADDR:
                        self.status = False

        # copy the binary data between obj.start and obj.end to obj.buffer
        def getData(self):
                """get data between start and end put them into object.buffer"""
                self.ogLen = self.end - self.start
                self.buffer = b''
                try:
                        self.buffer = idc.get_bytes(self.start, self.ogLen)
                except:
                        self.status = False
                return

        # the selected data is copied to the buffer in a binary format
        def run(self):
                """basically main"""
                self.checkBounds()
                if self.status == False:
                        sys.stdout.write('ERROR: Please select valid data\n')
                        return
                self.getData()

        # patch the IDB at obj.start with the argument data
        def patch(self, temp=None):
                """patch idb with data in object.buffer"""
                if temp != None:
                        self.buffer = temp
                        for index, byte in enumerate(self.buffer):
                                idc.patch_byte(self.start + index, ord(byte))

        # opens a file and saves the data in obj.buffer.
        def importb(self):
                '''import file to save to buffer'''
                fileName = ida_kernwin.ask_file(0, "*.*", 'Import File')
                try:
                        self.buffer = open(fileName, 'rb').read()
                except:
                        sys.stdout.write('ERROR: Cannot access file')

        # exports the data in obj.buffer to a save as file
        def export(self):
                '''save the selected buffer to a file'''
                exportFile = ida_kernwin.ask_file(1, "*.*", 'Export Buffer')
                f = open(exportFile, 'wb')
                f.write(self.buffer)
                f.close()

        # print
        def stats(self):
                print("start: 0x%x" % self.start)
                print("end: 0x%x" % self.end)
                print("len: 0x%x" % len(self.buffer))

Python>f = IO_DATA()
Python>f.stats()
start: 0x401063
end: 0x4010aa
len: 0x47
```

## PyQt
pass

## 生成批处理文件
```python
# batch_analysis.py
# 为目录下的所有文件创建 IDB 和 ASM 文件
import os
import subprocess
import glob
paths = glob.glob("*")
ida_path = os.path.join(os.environ['PROGRAMFILES'], "IDA Pro 7.5", "idat.exe")
for file_path in paths:
        if file_path.endswith(".py"):
                continue
        subprocess.call([ida_path, "-B", file_path])

"""
# 执行结果
C:\injected>python batch_analysis.py
Thank you for using IDA. Have a nice day!

C:\injected>dir
0?/**/____ 09:30 AM <DIR> .
0?/**/____ 09:30 AM <DIR> ..
0?/**/____ 09:30 AM 506,142 bad_file.asm
0?/**/____ 10:48 AM 167,936 bad_file.exe
0?/**/____ 09:30 AM 1,884,601 bad_file.idb
0?/**/____ 09:29 AM 270 batch_analysis.py
0?/**/____ 09:30 AM 682,602 injected.asm
0?/**/____ 06:55 PM 104,889 injected.dll
0?/**/____ 09:30 AM 1,384,765 injected.idb
"""
```

## 执行脚本
```python
# 计算 IDB 中的指令数并写入文件 instru_count.txt

# count.py
import idc
import idaapi
import idautils

idaapi.auto_wait()
count = 0
for func in idautils.Functions():
        # Ignore Library Code
        flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
        if flags & FUNC_LIB:
                continue
        for instru in idautils.FuncItems(func):
                count += 1
f = open("instru_count.txt", 'w')
print_me = "Instruction Count is %d" % (count)
f.write(print_me)
f.close()
idc.qexit(0)
```
```python
# command line (idb; exe)
>"C:\Program Files\IDA Pro 7.5\ida.exe" -Scount.py example.idb
>"C:\Program Files\IDA Pro 7.5\ida.exe" -A -Scount.py example.exe

# instru_count.txt
Instruction Count is 186328
```

## Yara
```python
# yara 规则扫描文件
import yara
rules = yara.compile(source=signature)
data = open(scan_me, "rb").read()
matches = rules.match(data=self.mem_results)
print(match(es))
```
```python
# 读取 IDB 二进制数据，使用 yara 扫描数据
import yara
import idautils

SEARCH_CASE = 4
SEARCH_REGEX = 8
SEARCH_NOBRK = 16
SEARCH_NOSHOW = 32
SEARCH_UNICODE = 64
SEARCH_IDENT = 128
SEARCH_BRK = 256

class YaraIDASearch:
        def __init__(self):
                self.mem_results = ""
                self.mem_offsets = []
                if not self.mem_results:
                        self._get_memory()
        
        def _get_memory(self):
                print("Status: Loading memory for Yara.")
                result = b""
                segments_starts = [ea for ea in idautils.Segments()]
                offsets = []
                start_len = 0
                for start in segments_starts:
                        end = idc.get_segm_end(start)
                        result += idc.get_bytes(start, end - start)
                        offsets.append((start, start_len, len(result)))
                        start_len = len(result)
                print("Status: Memory has been loaded.")
                self.mem_results = result
                self.mem_offsets = offsets

        def _to_virtual_address(self, offset, segments):
                va_offset = 0
                for seg in segments:
                        if seg[1] <= offset < seg[2]:
                                va_offset = seg[0] + (offset - seg[1])
                return va_offset

        def _init_sig(self, sig_type, pattern, sflag):
                if SEARCH_REGEX & sflag:
                        signature = "/%s/" % pattern
                        if SEARCH_CASE & sflag:
                                # ida is not case sensitive by default but yara is
                                pass
                        else:
                                signature += " nocase"
                        if SEARCH_UNICODE & sflag:
                                signature += " wide"
                elif sig_type == "binary":
                        signature = "{ %s }" % pattern
                elif sig_type == "text" and (SEARCH_REGEX & sflag) == False:
                        signature = '"%s"' % pattern
                        if SEARCH_CASE & sflag:
                                pass
                        else:
                                signature += " nocase"
                        signature += " wide ascii"
                yara_rule = "rule foo : bar { strings: $a = %s condition: $a }" % signature
                return yara_rule

        def _compile_rule(self, signature):
                try:
                        rules = yara.compile(source=signature)
                except Exception as e:
                        print("ERROR: Cannot compile Yara rule %s" % e)
                        return False, None
                return True, rules

        def _search(self, signature):
                status, rules = self._compile_rule(signature)
                if not status:
                        return False, None
                values = []
                matches = rules.match(data=self.mem_results)
                if not matches:
                        return False, None
                for rule_match in matches:
                        for match in rule_match.strings:
                                match_offset = match[0]
                                values.append(self._to_virtual_address(match_offset, self.mem_offsets))
                return values

        def find_binary(self, bin_str, sflag=0):
                yara_sig = self._init_sig("binary", bin_str, sflag)
                offset_matches = self._search(yara_sig)
                return offset_matches

        def find_text(self, q_str, sflag=0):
                yara_sig = self._init_sig("text", q_str, sflag)
                offset_matches = self._search(yara_sig)
                return offset_matches

        def find_sig(self, yara_rule):
                offset_matches = self._search(yara_rule)
                return offset_matches

        def reload_scan_memory(self):
                self._get_memory()

# 测试
Python>ys = YaraIDASearch()
Status: Loading memory for Yara.
Status: Memory has been loaded.
Python>example_rule = """rule md5_constant
{
        strings:
                $hex_constant = { 01 23 45 67 } // byte pattern 
        condition:
                $hex_constant
}"""
Python>
Python>ys.find_sig(example_rule)
[4199976L]
```

## Unicorn Engine
```python
# 初始化Unicorn实例
mu = Uc(UC_ARCH, UC_MODE)

# 映射内存
uc.mem_map(address, size, perms=uc.UC_PROT_ALL)
uc.mem_unmap(address, size)
# 读/写内存
uc.mem_read(address, size)
uc.mem_write(address, data)

# 读/写寄存器
uc.reg_read(reg_id, opt=None)
uc.reg_write(reg_id, value)

# 启动/停止仿真
uc.emu_start(begin, until, timeout=0, count=0) 
uc.emu_stop()
```
```python
# 使用用户定义的回调进行内存和hook管理
hook = uc.hook_add(UC_HOOK_*, callback, user_data, begin, end, ...)
emu.hook_del(hook)

# UC_HOOK_INTR: hook 所有中断和系统调用事件
def hook_intr(uc, intno, user_data):
        # only handle Linux syscall
        if intno != 0x80:
                print("got interrupt %x ???" %intno);
                uc.emu_stop()
                return
uc.hook_add(UC_HOOK_INTR, hook_intr)

# UC_HOOK_INSN: 在执行 x86 指令 IN、OUT 或 SYSCALL 时添加 hook
def hook_syscall(uc, user_data):
        rax = uc.reg_read(UC_X86_REG_RAX)
        if rax == 0x100:
                uc.reg_write(UC_X86_REG_RAX, 0x200)
uc.hook_add(UC_HOOK_INSN, hook_syscall, None,1, 0, UC_X86_INS_SYSCALL)

# UC_HOOK_CODE: 在执行每条指令之前调用 hook
def hook_code(uc, address, size, user_data):
        print("Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
uc.hook_add(UC_HOOK_CODE, hook_code)

# UC_HOOK_BLOCK: 实现用于跟踪基本块的回调
def hook_block(uc, address, size, user_data):
        print("Tracing basic block at 0x%x, block size = 0x%x" %(address, size))
uc.hook_add(UC_HOOK_BLOCK, hook_block)

# UC_HOOK_MEM_*: 专门用于读取、获取、写入和访问内存的钩子
def hook_mem_example(uc, access, address, size, value, user_data):
        pass

# UC_HOOK_MEM_INVALID: 发生无效的内存访问时，执行回调
def hook_mem_invalid(uc, access, address, size, value, user_data):
        eip = uc.reg_read(UC_X86_REG_EIP)
        if access == UC_MEM_WRITE:
                print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
        if access == UC_MEM_READ:
                print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip,size))
        return False
uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

# UC_HOOK_MEM_READ_UNMAPPED: 尝试读取未映射的内存时执行回调
def hook_mem_read_unmapped(uc, access, address, size, value, user_data):
        pass
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped, None)
```
```python
"""
# 调用 malloc 分配内存; 复制加密字符串的偏移量; 使用密钥对字符串的每个字节进行异或运算; 将结果存储在分配的内存中
.text:00401034 push esi
.text:00401035 push edi
.text:00401036 push 0Ah ; Size
.text:00401038 call ds:malloc
.text:0040103E mov esi, eax
.text:00401040 mov edi, offset str_encrypted
.text:00401045 xor eax, eax ; eax = 0
.text:00401047 sub edi, esi
.text:00401049 pop ecx
.text:0040104A
.text:0040104A loop: ; CODE XREF: _main+28↓j
.text:0040104A lea edx, [eax+esi]
.text:0040104D mov cl, [edi+edx]
.text:00401050 xor cl, ds:b_key
.text:00401056 inc eax
.text:00401057 mov [edx], cl
.text:00401059 cmp eax, 9 ; index
.text:0040105C jb short loop
.text:0040105E push esi
"""

# 使用 Unicorn Engine 解密内存数据（已高亮选择了 0x401034 到 0x40105e 的汇编代码）
from unicorn import *
from unicorn.x86_const import *
import idautils
import math

VIRT_MEM = 0x4000

def roundup(x):
        return int(math.ceil(x / 1024.0)) * 1024

def hook_mem_invalid(uc, access, address, size, value, user_data):
        if uc._arch == UC_ARCH_X86:
                eip = uc.reg_read(UC_X86_REG_EIP)
        else:
                eip = uc.reg_read(UC_X86_REG_RIP)
        bb = uc.mem_read(eip, 2)
        if bb != b"\xFF\x15":
                return
        if idc.get_name(address) == "malloc":
                uc.mem_map(VIRT_MEM, 8 * 1024)
        if uc._arch == UC_ARCH_X86:
                uc.reg_write(UC_X86_REG_EAX, VIRT_MEM)
                cur_addr = uc.reg_read(UC_X86_REG_EIP)
                uc.reg_write(UC_X86_REG_EIP, cur_addr + 6)
        else:
                cur_addr = uc.reg_read(UC_X86_REG_RIP)
                uc.reg_write(UC_X86_REG_RIP, cur_addr + 6)

def hook_code(uc, address, size, user_data):
        """For Debugging Use Only"""
        print('Tracing instruction at 0x%x, instruction size = 0x%x' % (address, size))

def emulate():
        try:
                # get segment start and end address
                segments = []
                for seg in idautils.Segments():
                        segments.append((idc.get_segm_start(seg), idc.get_segm_end(seg)))
                # get base address
                BASE_ADDRESS = idaapi.get_imagebase()
                # get bit
                info = idaapi.get_inf_structure()
                if info.is_64bit():
                        mu = Uc(UC_ARCH_X86, UC_MODE_64)
                elif info.is_32bit():
                        mu = Uc(UC_ARCH_X86, UC_MODE_32)
                # map 8MB memory for this emulation
                mu.mem_map(BASE_ADDRESS - 0x1000, 8 * 1024 * 1024)
                # write segments to memory
                for seg in segments:
                        temp_seg = idc.get_bytes(seg[0], seg[1] - seg[0])
                        mu.mem_write(seg[0], temp_seg)

                # initialize stack
                stack_size = 1024 * 1024
                if info.is_64bit():
                        stack_base = roundup(seg[1])
                        mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 0x1000)
                        mu.reg_write(UC_X86_REG_RBP, stack_base + stack_size)
                elif info.is_32bit():
                        stack_base = roundup(seg[1])
                        mu.reg_write(UC_X86_REG_ESP, stack_base + stack_size - 0x1000)
                        mu.reg_write(UC_X86_REG_EBP, stack_base + stack_size)
                # write null bytes to the stack
                mu.mem_write(stack_base, b"\x00" * stack_size)

                # get selected address range
                start = idc.read_selection_start()
                end = idc.read_selection_end()
                if start == idc.BADADDR:
                        return
                # add hook
                mu.hook_add(UC_HOOK_MEM_READ, hook_mem_invalid)
                mu.hook_add(UC_HOOK_CODE, hook_code)

                mu.emu_start(start, end)
                decoded = mu.mem_read(VIRT_MEM, 0x0A)
                print(decoded)
        except UcError as e:
                print("ERROR: %s" % e)
                return None
        return mu
emulate()

"""
# output
Tracing instruction at 0x401034, instruction size = 0x1
Tracing instruction at 0x401035, instruction size = 0x1
Tracing instruction at 0x401036, instruction size = 0x2
..removed..
Tracing instruction at 0x401059, instruction size = 0x3
Tracing instruction at 0x40105c, instruction size = 0x2
Tracing instruction at 0x40105e, instruction size = 0x1
bytearray(b'test mess\x00')
"""
```