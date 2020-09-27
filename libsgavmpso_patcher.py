from __future__ import print_function
import numpy as np
from unicorn import *
from unicorn.arm64_const import *
from ida_auto import *
from arc4 import ARC4
def get_cipher(begin, length):
    code = b''
    index = 0
    for b in get_bytes(begin, (begin+length), 0):
        code += b
    return code

def decrypt(cipher):
    arc4 = ARC4('DcO/lcK+h?m3c*q@')
    plain = arc4.decrypt(cipher)
    return plain

def do_rc4_decrypt(length_addr, end_addr):
    while length_addr <= end_addr:
        cipher_addr = length_addr + 1
        length = Byte(length_addr)
        cipher = get_cipher(cipher_addr, length)
        plain = decrypt(cipher)
        plain = plain[:length]
        print("afterdecrypt: {} {}".format(hex(cipher_addr), plain))
        if plain != "":
            MakeArray(cipher_addr, length+1)
            MakeComm(cipher_addr, plain)
        length_addr += length + 2

def get_regnum(reg_name):
    ri = idaapi.reg_info_t()
    idaapi.parse_reg_name("X0", ri)
    x0 = ri.reg
    idaapi.parse_reg_name(reg_name, ri)
    sub = ri.reg - x0
    return sub

# FlowChart需要function作为参数，但花指令有时不能转换为function，因此需要自己查找ADD->ADR->LDRSW ADR->MOV
# 当前指令为RET时，需要先找到MOV X30, X12这种赋值语句，然后再向上
def find_basicblock_EA_my(addr):
    ea = find_basicblock_EA(addr)
    if ea != -1:
        if ea == 0:
            return -1
        return ea
    br_reg = idc.GetOpnd(addr, 0)
    pre_br = addr - 4
    while pre_br:
        if "RET" == idc.GetMnem(addr):
            br_reg = idc.GetOpnd(addr - 4, 1)
        if (("ADD" == idc.GetMnem(pre_br)) and (br_reg == idc.GetOpnd(pre_br, 0))):
            break
        pre_br -= 4
    add_left_reg = idc.GetOpnd(pre_br, 1)
    add_right_reg = idc.GetOpnd(pre_br, 2)
    # ADD左值总是从ADR赋值
    while ("ADR" != idc.GetMnem(pre_br)) or (add_left_reg != idc.GetOpnd(pre_br, 0)):
        pre_br -= 4
    ea = pre_br + 4
    print("[i] br block EA: %x" % ea)
    return ea

def find_basicblock_EA(addr):
    f = idaapi.get_func(addr)
    if not f:
        return -1
    fc = idaapi.FlowChart(f)
    pred_block_ea = 0
    for block in fc:
        if block.startEA <= addr:
            if (block.endEA > addr):
                print("[i] basicblock.EA: {}".format(hex(block.startEA)))
                if (block.startEA == f.startEA):
                    return 0
                return block.startEA

def find_pred_basicblock_EA(addr):
    pred_block_ea = find_basicblock_EA(addr) - 4
    if pred_block_ea < 0:
        return
    pred_block_ea = find_basicblock_EA(pred_block_ea)
    print("[i] pred_blocks: {}".format(hex(pred_block_ea)))
    return pred_block_ea

def unicorn_calc(begin, end, adr_addr, ldr_addr, br_addr):
    code = b''
    index = 0
    for b in get_bytes(begin, (end-begin), 0):
        if index >= (adr_addr-begin) and index < (ldr_addr-begin+4):
            index += 1
            continue
        code += b
        index += 1
    ADDRESS = 0x400000
    STACK_BASE = 0
    STACK_SIZE = 1024*1024
    try:
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2*1024 * 1024)
        mu.mem_map(STACK_BASE, 2*STACK_SIZE)
        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)
        mu.reg_write(UC_ARM64_REG_SP, STACK_SIZE-1)
        mu.reg_write(UC_ARM64_REG_X29, STACK_SIZE-1 + 0x500)
        mu.reg_write(UC_ARM64_REG_X22, STACK_SIZE-1 + 0x500 + 0x2f0)
        mu.reg_write(UC_ARM64_REG_X0 + get_regnum(idc.GetOpnd(adr_addr, 0)), idc.GetOperandValue(adr_addr, 1))
        ldr_reg = idc.GetOpnd(ldr_addr, 0)
        ldr_value_addr = idc.GetOperandValue(ldr_addr, 1)
        ldr_value = np.int32(idc.Dword(ldr_value_addr))
        if idc.Dword(ldr_value_addr) != ldr_value:
            ldr_value = int(ldr_value)
        else:
            ldr_value = idc.Dword(ldr_value_addr)
        #print("ldr_value", hex(ldr_value))
        mu.reg_write(UC_ARM64_REG_X0 + get_regnum(ldr_reg), ldr_value)
        mu.emu_start(ADDRESS, ADDRESS + len(code))
        br_value = mu.reg_read(UC_ARM64_REG_X0 + get_regnum(idc.GetOpnd(br_addr, 0)))
        if "RET" == idc.GetMnem(br_addr):
            br_value = mu.reg_read(UC_ARM64_REG_X30)
        print('[i] br value: ' , hex(br_value), mu.reg_read(UC_ARM64_REG_X18))
        return br_value
    except Exception as e:
        print('[e] %s' % e)
        return 0

def find_br_and_patch(br_addr):
    try:
        # 将br指令所在的block的前序block作为local function的开始位置
        ea = find_basicblock_EA_my(br_addr)
        if ea <= 0:
            return
        begin_ea = ea - 8
        if "STUR" == idc.GetMnem(begin_ea) or "STR" == idc.GetMnem(begin_ea):
            pass
        elif "SUB" == idc.GetMnem(begin_ea):
            if ("STUR" == idc.GetMnem(begin_ea - 4) or "STR" == idc.GetMnem(begin_ea - 4)) and (GetOpnd(begin_ea, 1) in GetOpnd(begin_ea-4, 1) and str(hex(np.int32(GetOperandValue(begin_ea, 2)))) in GetOpnd(begin_ea-4, 1)):
                begin_ea = begin_ea - 4
        else:
            print("[i] Unnormal ADR->STUR %x" % begin_ea)
            return
        stur_left = idc.GetOpnd(begin_ea, 0)
        while ("MOV" != idc.GetMnem(begin_ea)) or (stur_left != idc.GetOpnd(begin_ea, 0)):
            begin_ea -= 4
            if br_addr - begin_ea > 0x80:
                print("[e] beign_ea not found")    
                return
        
        for addr in range(begin_ea, ea, 4):
            if "BL" == idc.GetMnem(addr) or "BLR" == idc.GetMnem(addr) or "B" == idc.GetMnem(addr) or "B." in idc.GetMnem(addr):
                # 如果前序block中有函数调用，则先略过之后手动处理
                print("[e] function call exits: %x" % addr)
                return
        if br_addr:
            ldr_addr = ea
            adr_addr = ldr_addr - 4
            if idc.GetOpnd(begin_ea, 0)[1:] == idc.GetOpnd(ldr_addr, 0)[1:]:
                # MOV语句与LDRSW语句的寄存器序号一致，会导致unicorn模拟时寄存器值覆盖，故跳过
                print('[e]: MOV == LDRSW')
                return
            print("[i] ", hex(begin_ea), hex(br_addr), hex(adr_addr), hex(ldr_addr), br_addr)
            addr = unicorn_calc(begin_ea, br_addr, adr_addr, ldr_addr, br_addr)
            #addr = 0
            
            if addr == 0:
                return
            print("[i] {} br to: {}".format(hex(br_addr), hex(addr)))
            tmp = br_addr
            if (addr - tmp) >= 0x48 or (addr - tmp) <= 0x10:
                print("[e] may be wrong {}, unkonwn stack offset ?".format(hex(addr)))
                return 
            ida_bytes.patch_dword(adr_addr, 0xAA0103E1)
            ida_bytes.patch_dword(ldr_addr, 0xAA0103E1)
            while tmp < int(addr):
                ida_bytes.patch_dword(tmp, 0xAA0103E1)
                tmp += 4
            try:
                idc.create_byte(br_addr + 4)
                idc.MakeCode(br_addr + 4)
            except Exception as e:
                print("[i] %s" % e)
                return
    except Exception as e:
        print("[i] %s" % e)
        return

def patch():
    begin = 0xa3e74
    
    end = 0xa40f4
    # 从begin遍历BR指令，每条BR指令进行find_br_and_patch
    for addr in range(begin, end, 4):
        if idc.MakeCode(addr) == 0:
            continue
        if (("BR" in idc.GetMnem(addr)) or ("BLR" in idc.GetMnem(addr))or ("RET" in idc.GetMnem(addr))) and (idc.MakeCode(addr+4) == 0):
            find_br_and_patch(addr)

def patcher_switch(start_addr, bl_addr):
    index = Dword(GetOperandValue(bl_addr-4, 1))
    index += 1
    offset = Dword(start_addr + (index << 2))
    target_addr = start_addr + offset
    ida_bytes.patch_dword(start_addr + (index << 2), 0xAA0103E1)
    print("0x%x switch patcher to: b 0x%x" % (bl_addr, target_addr))
    ida_bytes.patch_dword(bl_addr-8, 0xAA0103E1)
    ida_bytes.patch_dword(bl_addr-4, 0xAA0103E1)
    ida_bytes.patch_dword(bl_addr+4, 0xAA0103E1)
    idc.MakeCode(bl_addr+4)
    ida_bytes.patch_dword(target_addr, 0xAA0103E1)
    return target_addr
    
#do_rc4_decrypt(0xD3dda, 0xD3ddb)

#patch()
patcher_switch(0xB3E14, 0xb3eb8 )