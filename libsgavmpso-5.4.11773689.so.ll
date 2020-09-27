source_filename = "test"
target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"

@global_var_1870 = local_unnamed_addr global i64 -5764605115004650512
@global_var_1 = global i64 1103844756549
@global_var_20a = local_unnamed_addr global i64 1636495880981250048
@global_var_214 = local_unnamed_addr global i64 -3441314458434488022
@global_var_21c = local_unnamed_addr global i64 3375977406367945266
@global_var_224 = local_unnamed_addr global i64 287762808832
@global_var_22c = local_unnamed_addr global i64 25769803852
@global_var_239 = local_unnamed_addr global i64 4899916394813980672
@global_var_e = local_unnamed_addr global i64 282260955922432
@global_var_27c = local_unnamed_addr global i64 184683593775
@global_var_19 = local_unnamed_addr global i64 4611686018427387932
@global_var_0 = global i64 282584257676671
@global_var_46a88 = local_unnamed_addr global i64* @global_var_0
@global_var_1b = local_unnamed_addr global i64 70368744177664
@global_var_8 = local_unnamed_addr global i64* @global_var_0
@global_var_1a = local_unnamed_addr global i64 18014398509481984
@global_var_46a90 = local_unnamed_addr global i64 7312
@global_var_1c = local_unnamed_addr global i64 274877906944
@global_var_10 = local_unnamed_addr global i64 4306960387
@global_var_10102 = global i64 -432221308722402815
@global_var_4 = local_unnamed_addr global i64* @global_var_10102
@global_var_228 = local_unnamed_addr global i64 326417514563
@global_var_101 = global i64 2594073385365405698
@global_var_5 = local_unnamed_addr global i64* @global_var_101
@global_var_b90 = local_unnamed_addr global i64 7376721884347326208
@global_var_6 = local_unnamed_addr global i64* @global_var_1
@global_var_47000 = global i64* @global_var_0
@global_var_28 = local_unnamed_addr global i64 226752
@global_var_1e2c = local_unnamed_addr global i64 -7997853397573172939
@global_var_1e50 = local_unnamed_addr global i64 7954105546146054345
@global_var_1eca = local_unnamed_addr global i64 -5969150759168093568
@global_var_7c = local_unnamed_addr global i64 961557278228486
@global_var_1f8c = local_unnamed_addr global i64 -7997576037175131849
@global_var_1fb0 = local_unnamed_addr global i64 3631988954414186450
@global_var_2069 = local_unnamed_addr global i64 -4570870480357474285
@global_var_2089 = local_unnamed_addr global i64 -168597670084410281
@global_var_f6 = local_unnamed_addr global i64 33554432
@0 = external global i32
@global_var_93 = local_unnamed_addr global i32 0
@global_var_5f = local_unnamed_addr global i32 56811520
@global_var_87 = local_unnamed_addr global i32 74090496

define void @function_1900(i64* %d) local_unnamed_addr {
dec_label_pc_1900:
  call void @__cxa_finalize(i64* %d), !insn.addr !0
  ret void, !insn.addr !0
}

define i64 @entry_point() local_unnamed_addr {
dec_label_pc_1c90:
  call void @__cxa_finalize(i64* bitcast (i64** @global_var_47000 to i64*)), !insn.addr !1
  ret i64 ptrtoint (i32* @0 to i64), !insn.addr !1
}

define i64 @JNI_OnLoad() local_unnamed_addr {
dec_label_pc_1df8:
  %0 = call i64 @__decompiler_undefined_function_0()
  %1 = call i64 @__decompiler_undefined_function_0()
  %2 = call i64 @__decompiler_undefined_function_0()
  %3 = call i64 @__asm_mrs(i64 %1, i64 %0), !insn.addr !2
  ret i64 %2, !insn.addr !3
}

define i64 @JNI_OnUnload() local_unnamed_addr {
dec_label_pc_1f54:
  %0 = call i64 @__decompiler_undefined_function_0()
  %1 = call i64 @__decompiler_undefined_function_0()
  %2 = call i64 @__decompiler_undefined_function_0()
  %3 = call i64 @__asm_mrs(i64 %1, i64 %0), !insn.addr !4
  ret i64 %2, !insn.addr !5
}

declare void @__cxa_finalize(i64*) local_unnamed_addr

declare i64 @__asm_mrs(i64, i64) local_unnamed_addr

declare i64 @__decompiler_undefined_function_0() local_unnamed_addr

!0 = !{i64 6412}
!1 = !{i64 7320}
!2 = !{i64 7692}
!3 = !{i64 7756}
!4 = !{i64 8044}
!5 = !{i64 8108}
