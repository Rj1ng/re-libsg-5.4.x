# libsgmainso-5.4.11776953

## bugly

```c
sigaction_0(6, (const struct sigaction *)&sig_usr_SIGABRT, 0LL);// SIGABRT
sigaction_0(7, (const struct sigaction *)&sig_usr_SIGBUS, 0LL);
sigaction_0(8, (const struct sigaction *)&sig_usr_SIGFPE, 0LL);
sigaction_0(4, (const struct sigaction *)&sig_usr_SIGILL, 0LL);
sigaction_0(13, (const struct sigaction *)&sig_usr_SIGPIPE, 0LL);
sigaction_0(11, (const struct sigaction *)&sig_usr_SIGSEGV, 0LL);
sigaction_0(31, (const struct sigaction *)&sig_usr_SIGSYS, 0LL);
sigaction_0(5, (const struct sigaction *)&sig_usr_SIGTRAP, 0LL);
```

## 花指令

```assembly
LOAD:0000000000010D84                     LDRSW           X21, unk_10DAC
LOAD:0000000000010D88                     ADD             X21, X21, #0x7A
LOAD:0000000000010D8C                     SUB             X21, X21, #0x7C
LOAD:0000000000010D90                     LDRSW           X2, [X9]
LOAD:0000000000010D94                     SUB             X21, X21, X2
LOAD:0000000000010D98                     ADD             X12, X12, X21
LOAD:0000000000010D9C                     MOV             W5, #0x5F
LOAD:0000000000010DA0                     STR             W5, [X10]
LOAD:0000000000010DA4                     MOV             X30, X12

1. LOAD:0000000000010DA8                     RET
2. LOAD:0000000000010D4C                     BLR             X25
3. LOAD:00000000000111C0                     BR              X12
4. 以下，类似yunceng，通过function开始位置的跳转指令进入到函数原入口
LOAD:00000000000B5C90 000                 STP             X0, X30, [SP,#var_10]!
LOAD:00000000000B5C94 010                 BL              sub_B5C98
LOAD:00000000000B5C94     ; End of function sub_B5C90
LOAD:00000000000B5C94
LOAD:00000000000B5C98
LOAD:00000000000B5C98     ; =============== S U B R O U T I N E =======================================
LOAD:00000000000B5C98
LOAD:00000000000B5C98
LOAD:00000000000B5C98     sub_B5C98                               ; CODE XREF: sub_B5C90+4↑p
LOAD:00000000000B5C98 000                 ADR             X0, loc_B5CB0
LOAD:00000000000B5C9C 000                 MOV             X30, X0
LOAD:00000000000B5CA0 000                 RET
LOAD:00000000000B5CA0     ; End of function sub_B5C98
LOAD:00000000000B5CA0
LOAD:00000000000B5CA4     ; ---------------------------------------------------------------------------
LOAD:00000000000B5CA4                     MOV             X1, X1  ; Keypatch filled range [0xB5CA4:0xB5CAF] (12 bytes), replaced:
LOAD:00000000000B5CA4                                             ;   FNMADD S20, S10, S19, S20
LOAD:00000000000B5CA4                                             ;   DCB 3
LOAD:00000000000B5CA4                                             ;   DCB 0x1D
LOAD:00000000000B5CA4                                             ;   DCB 0x3D
LOAD:00000000000B5CA4                                             ;   DCB 0x1A
LOAD:00000000000B5CA4                                             ;   AND W8, W0, W10,LSL#21
LOAD:00000000000B5CA8                     MOV             X1, X1
LOAD:00000000000B5CAC                     MOV             X1, X1
LOAD:00000000000B5CB0
LOAD:00000000000B5CB0     loc_B5CB0 
```

```asm
LOAD:0000000000079F60 0C0                 MOV             W8, #0xB5
LOAD:0000000000079F68 0C0                 STUR            W8, [X29,#var_A8]
LOAD:0000000000079F6C 0C0                 ADR             X25, loc_79F70
LOAD:0000000000079F70
LOAD:0000000000079F70     loc_79F70                               ; DATA XREF: sub_79EA0+CC↑o
LOAD:0000000000079F70 0C0                 LDRSW           X2, =#0x276
LOAD:0000000000079F74 0C0                 SUB             X2, X2, #0xA1
LOAD:0000000000079F78 0C0                 SUB             X2, X2, #0xF3
LOAD:0000000000079F7C 0C0                 MOV             X9, #0x13
LOAD:0000000000079F80 0C0                 EOR             X2, X2, X9
LOAD:0000000000079F84 0C0                 LDRSW           X28, [X21]
LOAD:0000000000079F88 0C0                 SUB             X2, X2, X28

((0x276 - 0xa1 - 0xf3) ^ 0x13) - 0xb5 = 0x3c
((0x214 - 0xa1 - 0xf3) ^ 0x13) - 0x53 = 0x40
((0x2c6 - 0xa1 - 0xf3) ^ 0x13) - 0xe5 = 0x3c
```

```asm
LOAD:000000000007A138                     MOV             W9, #3
LOAD:000000000007A13C                     STUR            W9, [X29,#-0xA8]
LOAD:000000000007A140                     SUB             X9, X29, #0xA8
LOAD:000000000007A148                     ADR             X12, loc_7A14C
LOAD:000000000007A14C
LOAD:000000000007A14C     loc_7A14C                               ; DATA XREF: LOAD:000000000007A148↑o
LOAD:000000000007A14C                     LDRSW           X21, =0x3D
LOAD:000000000007A150                     ADD             X21, X21, #0x7A
LOAD:000000000007A154                     SUB             X21, X21, #0x7C
LOAD:000000000007A158                     LDRSW           X2, [X9]
LOAD:000000000007A15C                     SUB             X21, X21, X2
LOAD:000000000007A160                     ADD             X12, X12, X21

(0x3d + 0x7a - 0x7c) - 0x3 = 0x38
```

```asm
LOAD:0000000000084E18 040                 MOV             W9, #0x7F
LOAD:0000000000084E1C 040                 ADD             X10, SP, #0x30+var_2C
LOAD:0000000000084E28 040                 STR             W9, [SP,#0x30+var_2C]
LOAD:0000000000084E2C 040                 ADR             X11, loc_84E30
LOAD:0000000000084E30
LOAD:0000000000084E30     loc_84E30                               ; DATA XREF: sub_84DFC+30↑o
LOAD:0000000000084E30 040                 LDRSW           X3, =#0xffffffad
LOAD:0000000000084E34 040                 LDRSW           X25, [X10]
LOAD:0000000000084E38 040                 ADD             X3, X3, X25
LOAD:0000000000084E3C 040                 ADD             X11, X11, X3

0xffffffad + 0x7f = 
```

```asm
LOAD:00000000000831CC 070                 MOV             W9, #0xF4
LOAD:00000000000831D0 070                 SUB             X10, X29, #-var_58
LOAD:00000000000831DC 070                 STUR            W9, [X29,#var_58]
LOAD:00000000000831E0 070                 ADR             X5, loc_831E4
LOAD:00000000000831E4
LOAD:00000000000831E4     loc_831E4                               ; DATA XREF: sub_831AC+34↑o
LOAD:00000000000831E4 070                 LDRSW           X22, =#0xffffff62
LOAD:00000000000831E8 070                 ADD             X22, X22, #0xB6
LOAD:00000000000831EC 070                 MVN             X22, X22
LOAD:00000000000831F0 070                 ADD             X22, X22, #0xE1
LOAD:00000000000831F4 070                 LDRSW           X13, [X10]
LOAD:00000000000831F8 070                 EOR             X22, X22, X13
LOAD:00000000000831FC 070                 ADD             X5, X5, X22

((~(0xffffff62 + 0xb6)) + 0xe1) ^ 0xf4 = 0x3c
```

```asm
LOAD:0000000000083320                     MOV             W8, #0x54
LOAD:0000000000083324                     SUB             X9, X29, #0x58
LOAD:0000000000083328                     SUB             X10, X29, #0x54
LOAD:000000000008332C                     STUR            W8, [X29,#-0x58]
LOAD:0000000000083330                     ADR             X2, loc_83334
LOAD:0000000000083334
LOAD:0000000000083334     loc_83334                               ; DATA XREF: LOAD:0000000000083330↑o
LOAD:0000000000083334                     LDRSW           X22, =0x1F
LOAD:0000000000083338                     MVN             X22, X22
LOAD:000000000008333C                     LDRSW           X4, [X9]
LOAD:0000000000083340                     ADD             X22, X22, X4
LOAD:0000000000083344                     ADD             X2, X2, X22

(~ 0x1f) + 0x54 =  
```

```asm
STP X0, X30, [SP,#var_10]!	;花指令跳转入口
BL sub_B5DF0
0xB5DF0: ADR X0, sub_B5E00
MOV X30, X0
RET
DCB 0x3D	;无用数据
DCB 0x2F
DCB 0x20
DCB 0x3A
0xB5E00: LDP X0, X30, [SP+arg_0],#0x10	
STP X0, X30, [SP,#-0x10]!	;原函数入口
```

```asm
; 间接跳转表跳转
LOAD:00000000000B5E08  LDR W0, =3	; switch index
LOAD:00000000000B5E0C  BL sub_B4F88 
; sub_B4F88，switch函数
; STP             X0, X1, [SP,#var_10]!
; ADD             W0, W0, #1                               
; LDR             W0, [X30,W0,UXTW#2]
; ADD             X30, X30, W0,UXTW
; LDP             X0, X1, [SP+0x10+var_10],#0x10
; RET

; switch offset table
LOAD:00000000000B5E10 DCD 3
LOAD:00000000000B5E14 DCB 0x1C
; patch时将bl跳转改为b跳转，将栈平衡语句nop，将跳转表nop，再重建function
```



## Functions

```c
get_ro_build_version
v1 = dlopen_0("/system/lib64/libc.so", 2LL)
v3 = dlsym_0(v1, "__system_property_get")
v3("ro.build.version.release", &v11)
("ro.build.version.sdk", &v11)
```

## FunctionRelocations ?

```
struct function_relocation {
	char* functionName;
	void* functionAddr;
	int [] functionInfo; // 返回值个数，参数个数
}
LOAD:00000000000FB540                     DCQ aDladdr_0           ; "dladdr"
LOAD:00000000000FB548                     DCQ dladdr
LOAD:00000000000FB550                     DCB    2
LOAD:00000000000FB551                     DCB    0
LOAD:00000000000FB552                     DCB    0
LOAD:00000000000FB553                     DCB    0
LOAD:00000000000FB554                     DCB    1
LOAD:00000000000FB555                     DCB    0
LOAD:00000000000FB556                     DCB    0
LOAD:00000000000FB557                     DCB    0
LOAD:00000000000FB558                     DCB    0
LOAD:00000000000FB559                     DCB    0
LOAD:00000000000FB55A                     DCB    0
LOAD:00000000000FB55B                     DCB    0
LOAD:00000000000FB55C                     DCB    0
LOAD:00000000000FB55D                     DCB    0
LOAD:00000000000FB55E                     DCB    0
LOAD:00000000000FB55F                     DCB    0
```

##Structs

```c
struct UnknownFunctionsStruct_0x68
{
  void *malloc_ptr;
  int64_t size;
  uint64_t functions_ptr[11];
};
struct UnknownPthreadMutexStruct_0x18 {
  int64_t a;
  int64_t b;
  pthread_mutex_t* c;
};
```

## note

- [x] qword_1042B8在哪被赋值？各种函数指针引用它， 

  ​	*(_QWORD *)qword_1042B8[0] = sub_1540C;
  ​    *(_QWORD *)(qword_1042B8[0] + 8) = call_entry;
  ​    *(_QWORD *)(qword_1042B8[0] + 16) = entry;
  ​    *(_QWORD *)(qword_1042B8[0] + 24) = sub_15DE4;

- [x] sub_9EB28，table_decrypt字符串解密函数

- [ ] sub_399D4，这个函数是干嘛的？

- [ ] sub_6BA88以及前后的几个函数，都是和job相关逻辑，需要再观察

- [ ] sec_job文件夹下的一些文件读写操作需要再分析(0x6ac3c附近)，应该与update相关

## KeyLogic

- [ ] get_many_system_properties，获取很多system_property_get字段值

- [ ] register_sigactions，很多sig

- [ ] EdgeComputing ？

- [ ] dlopen("/system/lib64/libmediandk.so")，调用AMediaDrm_createByUUID

- [ ] root检测逻辑，check_root_security()

  ```c
  stat("/dev/socket/daemon.pid");
  if(ro.build.version.release != 52 && "samsung") {open("/system/bin/vold");}
  stat("/su/bin/su");
  ```

- [ ] deviceUniqueId逻辑分析
- [ ] LOCAL_DEVICE_INFO ?
- [ ] /proc/cpuinfo中"ARMv6"不存在，则执行exec_asm_in_cache
- [ ] check_aebi_by_libdlso，解析elf头部第18字节（e_machine字段），>= 40，则为arm架构，== 40为arm；> 40为arm64；== 3，则x86；== 62，则x64。https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
- [ ] 如果wifi.interface，则从/sys/class/net/(wlan0/eth1)/address获取LAN Mac，否则从(wlan/eth加数字遍历)/address获取
- [ ] socket ioctl(SIOCGIFHWADDR)获取MAC地址
- [ ] 通过ioctl获取broadcast PA address
- [ ] /data /dev/ /efs /storage的st_atime, st_mtime, st_ctime信息
- [ ] system_property_get(domain gateway ipaddress leastime mask mtu pid reason result server vendorInfo init.svc.dhcpcd net.hostname)，如dhcp.wlan0.vendorInfo
- [ ] zygote zygote64 system /init system_server /system/bin/servicemanager

##几个字段

- [ ] bizid

## config_json

- [ ] main_bizid
- [ ] job_priority
- [ ] job_type
- [ ] job_trigger
- [ ] trigger_action
- [ ] report_type
- [ ] schedule_count
- [ ] job_interval
- [ ] exe_type
- [ ] light_update
- [ ] version_limit
- [ ] app_version_limit

## status_json

- [ ] count
- [ ] last_run
- [ ] 

## anti debugger(check_proc_files)

1. /proc/self/status

   ```c
   // State:
   if ("R")
   	return 0;
   else if ("S")
   	return 1;
   else if ("T") {
   	if ("tracing")
   		return 2;
   	else if ("stopped")
   		return 6;
   } else if ("Z")
   	 return 3;
   else if ("D")
   	return 4;
   else return 5;
   ```

2. /proc/%d/stat

   ```c
   if ("R") return 0;
   if ("S") return 1;
   if ("D") return 4;
   if ("T") return 2;
   if ("Z") return 3;
   ```

   

3. /proc/%d/wchan，"ptrace_stop"时调试状态；"sys_epoll_wait"正常

4. /proc/self/cmdline，"/system/bin/debugger", "qihoo360", "com.lbe"

5. check_linker/linker64



