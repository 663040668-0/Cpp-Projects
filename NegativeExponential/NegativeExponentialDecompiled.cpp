/** 
*  Generator: vscode-decompiler@0.1.0 (https://marketplace.visualstudio.com/items?itemName=tintinweb.vscode-decompiler)
*  Target:    d:\C++ Projects\NegativeExponential\NegativeExponential.exe
**/

/* Function: __tmainCRTStartup */
int __tmainCRTStartup(undefined *param_1,undefined *param_2,ulonglong param_3,ulonglong param_4)
// Maybe a .exe entry
{
  void **ppvVar1;
  int iVar2;
  longlong lVar3;
  bool bVar4;
  undefined *puVar5;
  undefined *puVar6;
  int iVar7;
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar8;
  char **ppcVar9;
  size_t sVar10;
  void *_Dst;
  undefined *puVar11;
  undefined *puVar12;
  undefined *puVar13;
  longlong lVar14;
  size_t _Size;
  char **ppcVar15;
  longlong unaff_GS_OFFSET;
  
  puVar5 = _refptr___native_startup_lock;
  lVar3 = *(longlong *)(*(longlong *)(unaff_GS_OFFSET + 0x30) + 8);
  while( true ) {
    LOCK();
    lVar14 = *(longlong *)puVar5;
    if (lVar14 == 0) {
      *(longlong *)puVar5 = lVar3;
      lVar14 = 0;
    }
    puVar12 = _refptr___xi_z;
    puVar11 = _refptr___xi_a;
    puVar6 = _refptr___native_startup_state;
    UNLOCK();
    if (lVar14 == 0) break;
    if (lVar3 == lVar14) {
      bVar4 = true;
      iVar2 = *(int *)_refptr___native_startup_state;
joined_r0x000140001331:
      if (iVar2 == 1) {
        puVar11 = (undefined *)0x1f;
        _amsg_exit(0x1f);
        iVar2 = *(int *)puVar6;
        puVar12 = _refptr___xc_a;
        puVar13 = _refptr___xc_z;
      }
      else {
        if (*(int *)_refptr___native_startup_state == 0) {
          *(undefined4 *)_refptr___native_startup_state = 1;
          _initterm();
        }
        else {
          has_cctor = 1;
          puVar11 = param_1;
          puVar12 = param_2;
        }
        iVar2 = *(int *)puVar6;
        param_2 = puVar12;
        puVar12 = _refptr___xc_a;
        puVar13 = _refptr___xc_z;
      }
      _refptr___xc_a = puVar12;
      _refptr___xc_z = puVar13;
      if (iVar2 == 1) {
        _initterm();
        *(undefined4 *)puVar6 = 2;
        puVar11 = puVar12;
        param_2 = puVar13;
      }
      if (!bVar4) {
        LOCK();
        *(undefined8 *)puVar5 = 0;
        UNLOCK();
      }
      if (*(code **)_refptr___dyn_tls_init_callback != (code *)0x0) {
        param_3 = 0;
        param_2 = (undefined *)0x2;
        puVar11 = (undefined *)0x0;
        (**(code **)_refptr___dyn_tls_init_callback)();
      }
      _pei386_runtime_relocator(puVar11,param_2,param_3,param_4);
      pPVar8 = SetUnhandledExceptionFilter
                         ((LPTOP_LEVEL_EXCEPTION_FILTER)_refptr__gnu_exception_handler);
      *(LPTOP_LEVEL_EXCEPTION_FILTER *)_refptr___mingw_oldexcpt_handler = pPVar8;
      _set_invalid_parameter_handler((_invalid_parameter_handler)&LAB_140001000);
      fpreset();
      iVar7 = argc;
      iVar2 = argc + 1;
      _Size = (longlong)iVar2 * 8;
      ppcVar9 = (char **)malloc(_Size);
      lVar3 = (longlong)argv;
      ppcVar15 = ppcVar9;
      if (0 < iVar7) {
        lVar14 = 0;
        do {
          sVar10 = strlen(*(char **)(lVar3 + lVar14));
          _Dst = malloc(sVar10 + 1);
          *(void **)((longlong)ppcVar9 + lVar14) = _Dst;
          ppvVar1 = (void **)(lVar3 + lVar14);
          lVar14 = lVar14 + 8;
          memcpy(_Dst,*ppvVar1,sVar10 + 1);
        } while (_Size - 8 != lVar14);
        ppcVar15 = ppcVar9 + (longlong)iVar2 + -1;
      }
      *ppcVar15 = (char *)0x0;
      argv = ppcVar9;
      __main();
      iVar2 = argc;
      ppcVar15 = envp;
      **(undefined8 **)_refptr___imp___initenv = envp;

      // Here we are calling main()
      mainret = main(iVar2,argv,ppcVar15);
      if (managedapp != 0) {
        if (has_cctor != 0) {
          return mainret;
        }
        _cexit();
        return mainret;
      }
                    /* WARNING: Subroutine does not return */
      exit(mainret);

    }
    param_1 = (undefined *)0x3e8;
    Sleep(1000);
  }
  bVar4 = false;
  iVar2 = *(int *)_refptr___native_startup_state;
  goto joined_r0x000140001331;
}

/* Function: mainCRTStartup */
void mainCRTStartup(undefined *param_1,undefined *param_2,ulonglong param_3,ulonglong param_4)

{
  *(undefined4 *)_refptr___mingw_app_type = 0;
  __tmainCRTStartup(param_1,param_2,param_3,param_4);
  return;
}

/* Function: atexit */
int __cdecl atexit(_func_5014 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = _onexit((_onexit_t)param_1);
  return -(uint)(p_Var1 == (_onexit_t)0x0);
}

/* Function: __gcc_register_frame */
void __gcc_register_frame(void)

{
  atexit((_func_5014 *)&__gcc_deregister_frame);
  return;
}

/* Function: main */
int __cdecl main(int _Argc,char **_Argv,char **_Env)

{
  int iVar1;
  basic_ostream *pbVar2;
  double dVar3;
  double dVar4;
  double local_28; // double k;
  double local_20; // double a;
  
  __main();

  // Using pbVar2 because it's a chain of command e.g., cout<<string<<string<<..

  //cout<<"a^x = -k"<<endl;
  pbVar2 = std::operator<<( (basic_ostream *)__fu1__ZSt4cout,"a^x = -k" ); /* Maybe converting basic string into some format to be display by <cout> through the <operator> */
  std::basic_ostream<char,std::char_traits<char>>::operator << /* cout is using the operator */
            ( /* Send list of strings to be perform */
              (basic_ostream<char,std::char_traits<char>> *)pbVar2, /* Cast the type a again to fit the mentioned <char,std::char_traits<char>> types  */
              (_func_basic_ostream_ptr_basic_ostream_ptr *)_refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_ /* Send endl (which is a function not a string) */
            );

  // cout<<"conditions: a > 0, a != 1, k > 0"<<endl;
  pbVar2 = std::operator<<((basic_ostream *)__fu1__ZSt4cout,"conditions: a > 0, a != 1, k > 0"); /* Convert to the same format */
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ( /* Reusing <pbVar2> */
              (basic_ostream<char,std::char_traits<char>> *)pbVar2, /* Cast pbVar2 ("conditions: a > 0, a != 1, k > 0") */
              (_func_basic_ostream_ptr_basic_ostream_ptr *)_refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_ /* Send endl */
            );

  // NOTE : <__fu1__ZSt4cout> seem to be something that specificially work with "cout" as its name said

  // cout<<"a: ";
  std::operator<<((basic_ostream *)__fu1__ZSt4cout,"a: ");

  // Now it's istream
  // cin>>a;
  std::basic_istream<char,std::char_traits<char>>::operator>>
            (
              (basic_istream<char,std::char_traits<char>> *)__fu0__ZSt3cin, /* Now it's <__fu0__ZSt3cin> format or operation (idk) */
              &local_20 /* Telling where to store the value from the input (& means to access the 'address' of <local_20>)*/
            );
  
  // cout<<"k: ";
  std::operator<<((basic_ostream *)__fu1__ZSt4cout,"k: ");

  // cin>>k;
  std::basic_istream<char,std::char_traits<char>>::operator>>
            (
              (basic_istream<char,std::char_traits<char>> *)__fu0__ZSt3cin,
              &local_28
            );
  
  // Now to if statement
  /* if (!(a > 0 && a != 1 && k > 0)) */
  if (((local_20 <= 0.0) || (local_20 == DAT_140004080)) || (local_28 <= 0.0)) { /* ! symbol just simply inverts every expression */
    pbVar2 = std::operator<<((basic_ostream *)__fu1__ZSt4cout,
                             "Error: Input isn\'t followed the conditions.");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar2,
               (_func_basic_ostream_ptr_basic_ostream_ptr *)
               _refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
    iVar1 = -1;
  }
  else {
    pbVar2 = std::operator<<((basic_ostream *)__fu1__ZSt4cout,"x = ");
    dVar3 = log(local_28);
    dVar4 = log(local_20);
    pbVar2 = (basic_ostream *)
             std::basic_ostream<char,std::char_traits<char>>::operator<<
                       ((basic_ostream<char,std::char_traits<char>> *)pbVar2,dVar3 / dVar4);
    pbVar2 = std::operator<<(pbVar2," + ");
    dVar3 = log(local_20);
    pbVar2 = (basic_ostream *)
             std::basic_ostream<char,std::char_traits<char>>::operator<<
                       ((basic_ostream<char,std::char_traits<char>> *)pbVar2,DAT_140004088 / dVar3);
    pbVar2 = std::operator<<(pbVar2,"i");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar2,
               (_func_basic_ostream_ptr_basic_ostream_ptr *)
               _refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
    system("pause");
    iVar1 = 0;
  }
  return iVar1;
}

/* Function: std::operator<< */
/* std::basic_ostream<char, std::char_traits<char> >&
   std::TEMPNAMEPLACEHOLDERVALUE(std::basic_ostream<char, std::char_traits<char> >&, char const*) */

basic_ostream * std::operator<<(basic_ostream *param_1,char *param_2)

{
  basic_ostream *pbVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140001660. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pbVar1 = std::operator<<(param_1,param_2);
  return pbVar1;
}

/* Function: std::endl<char,std::char_traits<char>> */
/* std::basic_ostream<char, std::char_traits<char> >& std::endl<char, std::char_traits<char>
   >(std::basic_ostream<char, std::char_traits<char> >&) */

basic_ostream * std::endl<char,std::char_traits<char>>(basic_ostream *param_1)

{
  basic_ostream *pbVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140001668. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pbVar1 = std::endl<char,std::char_traits<char>>(param_1);
  return pbVar1;
}

/* Function: std::basic_ostream<char,std::char_traits<char>>::operator<< */
/* std::basic_ostream<char, std::char_traits<char> >::TEMPNAMEPLACEHOLDERVALUE(double) */

void __thiscall
std::basic_ostream<char,std::char_traits<char>>::operator<<
          (basic_ostream<char,std::char_traits<char>> *this,double param_1)

{
                    /* WARNING: Could not recover jumptable at 0x000140001670. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  std::basic_ostream<char,std::char_traits<char>>::operator<<(this,param_1);
  return;
}

/* Function: std::basic_ostream<char,std::char_traits<char>>::operator<< */
/* std::basic_ostream<char, std::char_traits<char>
   >::TEMPNAMEPLACEHOLDERVALUE(std::basic_ostream<char, std::char_traits<char> >&
   (*)(std::basic_ostream<char, std::char_traits<char> >&)) */

void __thiscall
std::basic_ostream<char,std::char_traits<char>>::operator<<
          (basic_ostream<char,std::char_traits<char>> *this,
          _func_basic_ostream_ptr_basic_ostream_ptr *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x000140001678. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  std::basic_ostream<char,std::char_traits<char>>::operator<<(this,param_1);
  return;
}

/* Function: std::basic_istream<char,std::char_traits<char>>::operator>> */
/* std::basic_istream<char, std::char_traits<char> >::TEMPNAMEPLACEHOLDERVALUE(double&) */

void __thiscall
std::basic_istream<char,std::char_traits<char>>::operator>>
          (basic_istream<char,std::char_traits<char>> *this,double *param_1)

{
                    /* WARNING: Could not recover jumptable at 0x000140001680. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  std::basic_istream<char,std::char_traits<char>>::operator>>(this,param_1);
  return;
}

/* Function: __do_global_ctors */
void __do_global_ctors(void)
// Setup something
{
  code **ppcVar1;
  uint uVar2;
  ulonglong uVar3;
  code **ppcVar4;
  
  uVar2 = (uint)*(undefined8 *)_refptr___CTOR_LIST__;
  if (uVar2 == 0xffffffff) {
    uVar3 = 0;
    do {
      uVar2 = (uint)uVar3;
      uVar3 = (ulonglong)(uVar2 + 1);
    } while (*(longlong *)(_refptr___CTOR_LIST__ + uVar3 * 8) != 0);
  }
  if (uVar2 != 0) {
    ppcVar4 = (code **)(_refptr___CTOR_LIST__ + (ulonglong)uVar2 * 8);
    ppcVar1 = (code **)(_refptr___CTOR_LIST__ + ((ulonglong)uVar2 - (ulonglong)(uVar2 - 1)) * 8 + -8
                       );
    do {
      (**ppcVar4)();
      ppcVar4 = ppcVar4 + -1;
    } while (ppcVar4 != ppcVar1);
  }
  atexit((_func_5014 *)&__do_global_dtors);
  return;
}

/* Function: __main */
void __main(void)
// set initialized value to 1 and __do_global_ctors() thing
{
  if (initialized != 0) {
    return;
  }
  initialized = 1;
  __do_global_ctors();
  return;
}

/* Function: _setargv */
int __cdecl _setargv(void)
// Empty (?)
{
  return 0;
}

/* Function: __dyn_tls_dtor */
undefined8 __dyn_tls_dtor(undefined8 param_1,uint param_2)

{
  if ((param_2 != 3) && (param_2 != 0)) {
    return 1;
  }
  __mingw_TLScallback(param_1,param_2);
  return 1;
}

/* Function: __dyn_tls_init */
/* WARNING: Removing unreachable block (ram,0x0001400017e3) */
/* WARNING: Removing unreachable block (ram,0x0001400017e8) */
/* WARNING: Removing unreachable block (ram,0x0001400017f0) */
/* WARNING: Removing unreachable block (ram,0x0001400017f2) */
/* WARNING: Removing unreachable block (ram,0x0001400017fb) */

undefined8 __dyn_tls_init(undefined8 param_1,int param_2)

{
  if (*(int *)_refptr__CRT_MT != 2) {
    *(undefined4 *)_refptr__CRT_MT = 2;
  }
  if ((param_2 != 2) && (param_2 == 1)) {
    __mingw_TLScallback(param_1,1);
    return 1;
  }
  return 1;
}

/* Function: _matherr */
int __cdecl _matherr(_exception *_Except)

{
  double dVar1;
  double dVar2;
  double dVar3;
  char *pcVar4;
  FILE *_File;
  char *pcVar5;
  
  switch(_Except->type) {
  default:
    pcVar5 = "Unknown error";
    break;
  case 1:
    pcVar5 = "Argument domain error (DOMAIN)";
    break;
  case 2:
    pcVar5 = "Argument singularity (SIGN)";
    break;
  case 3:
    pcVar5 = "Overflow range error (OVERFLOW)";
    break;
  case 4:
    pcVar5 = "The result is too small to be represented (UNDERFLOW)";
    break;
  case 5:
    pcVar5 = "Total loss of significance (TLOSS)";
    break;
  case 6:
    pcVar5 = "Partial loss of significance (PLOSS)";
  }
  dVar1 = _Except->retval;
  dVar2 = _Except->arg2;
  dVar3 = _Except->arg1;
  pcVar4 = _Except->name;
  _File = (FILE *)__acrt_iob_func(2);
  fprintf(_File,"_matherr(): %s in %s(%g, %g)  (retval=%g)\n",pcVar5,pcVar4,dVar3,dVar2,dVar1);
  return 0;
}

/* Function: fpreset */
void __cdecl fpreset(void)

{
  return;
}

/* Function: __report_error */
void __report_error(char *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  FILE *pFVar1;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res10 = param_2;
  local_res18 = param_3;
  local_res20 = param_4;
  pFVar1 = (FILE *)__acrt_iob_func(2);
  fwrite("Mingw-w64 runtime failure:\n",1,0x1b,pFVar1);
  pFVar1 = (FILE *)__acrt_iob_func(2);
  vfprintf(pFVar1,param_1,(va_list)&local_res10);
                    /* WARNING: Subroutine does not return */
  abort();
}

/* Function: mark_section_writable */
void mark_section_writable(ulonglong param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4)

{
  BOOL BVar1;
  DWORD DVar2;
  ulonglong *puVar3;
  IMAGE_SECTION_HEADER *pIVar4;
  undefined4 *puVar5;
  IMAGE_DOS_HEADER *pIVar6;
  SIZE_T SVar7;
  PDWORD lpflOldProtect;
  longlong lVar8;
  undefined8 uVar9;
  uint uVar10;
  _MEMORY_BASIC_INFORMATION local_48;
  
  lVar8 = (longlong)(int)maxSections;
  if ((int)maxSections < 1) {
    lVar8 = 0;
  }
  else {
    param_4 = 0;
    puVar3 = (ulonglong *)(the_secs + 0x18);
    do {
      param_3 = *puVar3;
      if ((param_3 <= param_1) && (param_3 = param_3 + *(uint *)(puVar3[1] + 8), param_1 < param_3))
      {
        return;
      }
      uVar10 = (int)param_4 + 1;
      param_4 = (ulonglong)uVar10;
      puVar3 = puVar3 + 5;
    } while (uVar10 != maxSections);
  }
  pIVar4 = __mingw_GetSectionForAddress(param_1);
  if (pIVar4 == (IMAGE_SECTION_HEADER *)0x0) {
                    /* WARNING: Subroutine does not return */
    __report_error("Address %p has no image-section",param_1,param_3,param_4);
  }
  lVar8 = lVar8 * 0x28;
  puVar5 = (undefined4 *)(the_secs + lVar8);
  *(IMAGE_SECTION_HEADER **)(puVar5 + 8) = pIVar4;
  *puVar5 = 0;
  pIVar6 = _GetPEImageBase();
  uVar10 = pIVar4->VirtualAddress;
  *(char **)(the_secs + 0x18 + lVar8) = pIVar6->e_magic + uVar10;
  SVar7 = VirtualQuery(pIVar6->e_magic + uVar10,&local_48,0x30);
  if (SVar7 != 0) {
    if (((local_48.Protect - 4 & 0xfffffffb) != 0) && ((local_48.Protect - 0x40 & 0xffffffbf) != 0))
    {
      uVar9 = 0x40;
      if (local_48.Protect == 2) {
        uVar9 = 4;
      }
      lpflOldProtect = (PDWORD)(lVar8 + the_secs);
      *(PVOID *)(lpflOldProtect + 2) = local_48.BaseAddress;
      *(SIZE_T *)(lpflOldProtect + 4) = local_48.RegionSize;
      BVar1 = VirtualProtect(local_48.BaseAddress,local_48.RegionSize,(DWORD)uVar9,lpflOldProtect);
      if (BVar1 == 0) {
        DVar2 = GetLastError();
                    /* WARNING: Subroutine does not return */
        __report_error("  VirtualProtect failed with code 0x%x",(ulonglong)DVar2,uVar9,
                       lpflOldProtect);
      }
    }
    maxSections = maxSections + 1;
    return;
  }
                    /* WARNING: Subroutine does not return */
  __report_error("  VirtualQuery failed for %d bytes at address %p",
                 (ulonglong)(pIVar4->Misc).PhysicalAddress,*(undefined8 *)(the_secs + 0x18 + lVar8),
                 param_4);
}

/* Function: _pei386_runtime_relocator */
/* WARNING: Function: ___chkstk_ms replaced with injection: alloca_probe */

void _pei386_runtime_relocator
               (undefined8 param_1,undefined8 param_2,ulonglong param_3,ulonglong param_4)

{
  byte bVar1;
  ushort uVar2;
  DWORD flNewProtect;
  uint uVar3;
  int iVar4;
  SIZE_T dwSize;
  LPVOID lpAddress;
  longlong lVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined2 uVar8;
  uint uVar9;
  undefined6 extraout_var;
  ulonglong *puVar10;
  DWORD *pDVar11;
  uint uVar12;
  ulonglong uVar14;
  uint *puVar15;
  int *piVar16;
  longlong lVar17;
  int *piVar18;
  longlong *plVar19;
  int iVar20;
  undefined8 auStack_90 [5];
  longlong alStack_68 [2];
  undefined auStack_58 [12];
  DWORD local_4c [3];
  ulonglong uVar13;
  
  if (was_init_0 != 0) {
    return;
  }
  was_init_0 = 1;
  auStack_90[0] = 0x140001b77;
  uVar8 = __mingw_GetSectionCount();
  puVar7 = _refptr___RUNTIME_PSEUDO_RELOC_LIST_END__;
  puVar6 = _refptr___ImageBase;
  auStack_90[0] = 0x140001b8e;
  maxSections = 0;
  lVar5 = -((longlong)(int)CONCAT62(extraout_var,uVar8) * 0x28 + 0xfU & 0xfffffffffffffff0);
  the_secs = auStack_58 + lVar5;
  if ((longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ -
      (longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST__ < 8) {
    maxSections = 0;
    return;
  }
  uVar14 = (ulonglong)*(uint *)_refptr___RUNTIME_PSEUDO_RELOC_LIST__;
  piVar16 = (int *)_refptr___RUNTIME_PSEUDO_RELOC_LIST__;
  if ((longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ -
      (longlong)_refptr___RUNTIME_PSEUDO_RELOC_LIST__ < 0xc) {
LAB_140001bcd:
    if (*piVar16 == 0) {
      uVar9 = piVar16[1];
LAB_140001bda:
      if (uVar9 == 0) {
        uVar9 = piVar16[2];
        if (uVar9 != 1) {
                    /* WARNING: Subroutine does not return */
          *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001e8c;
          __report_error("  Unknown pseudo relocation protocol version %d.\n",(ulonglong)uVar9,
                         param_3,param_4);
        }
        puVar15 = (uint *)(piVar16 + 3);
        if (_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ <= puVar15) {
          maxSections = 0;
          return;
        }
        do {
          while( true ) {
            uVar9 = puVar15[2];
            puVar10 = (ulonglong *)(puVar6 + *puVar15);
            uVar13 = (ulonglong)uVar9 & 0xff;
            uVar12 = (uint)uVar13;
            uVar14 = *puVar10;
            plVar19 = (longlong *)(puVar6 + puVar15[1]);
            if (uVar12 != 0x20) break;
            uVar3 = *(uint *)plVar19;
            if ((int)uVar3 < 0) {
              lVar17 = ((ulonglong)uVar3 | 0xffffffff00000000) - (longlong)puVar10;
            }
            else {
              lVar17 = (ulonglong)uVar3 - (longlong)puVar10;
            }
            lVar17 = lVar17 + uVar14;
            if (((uVar9 & 0xc0) == 0) && ((0xffffffff < lVar17 || (lVar17 < -0x80000000))))
            goto LAB_140001cb3;
            *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001ddf;
            mark_section_writable((ulonglong)plVar19,(ulonglong)(uVar9 & 0xc0),param_3,uVar14);
            *(uint *)plVar19 = (uint)lVar17;
LAB_140001c62:
            puVar15 = puVar15 + 3;
            if (puVar7 <= puVar15) goto LAB_140001d40;
          }
          if (0x20 < uVar12) {
            if (uVar12 != 0x40) {
LAB_140001e72:
                    /* WARNING: Subroutine does not return */
              *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001e80;
              __report_error("  Unknown pseudo relocation bit size %d.\n",uVar13,param_3,uVar14);
            }
            lVar17 = (*plVar19 - (longlong)puVar10) + uVar14;
            if ((uVar9 & 0xc0) == 0) {
              uVar12 = 0;
              if (-1 < lVar17) goto LAB_140001cb3;
            }
            else {
              *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001df8;
              mark_section_writable((ulonglong)plVar19,(ulonglong)uVar9,param_3,uVar14);
              *plVar19 = lVar17;
            }
            goto LAB_140001c62;
          }
          if (uVar12 != 8) {
            if (uVar12 != 0x10) goto LAB_140001e72;
            uVar2 = *(ushort *)plVar19;
            if ((short)uVar2 < 0) {
              lVar17 = ((ulonglong)uVar2 | 0xffffffffffff0000) - (longlong)puVar10;
            }
            else {
              lVar17 = (ulonglong)uVar2 - (longlong)puVar10;
            }
            lVar17 = lVar17 + uVar14;
            if (((uVar9 & 0xc0) == 0) && ((lVar17 < -0x8000 || (0xffff < lVar17))))
            goto LAB_140001cb3;
            *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001c5f;
            mark_section_writable((ulonglong)plVar19,(ulonglong)(uVar9 & 0xc0),param_3,uVar14);
            *(ushort *)plVar19 = (ushort)lVar17;
            goto LAB_140001c62;
          }
          bVar1 = *(byte *)plVar19;
          if ((char)bVar1 < '\0') {
            lVar17 = ((ulonglong)bVar1 | 0xffffffffffffff00) - (longlong)puVar10;
          }
          else {
            lVar17 = (ulonglong)bVar1 - (longlong)puVar10;
          }
          lVar17 = lVar17 + uVar14;
          if (((uVar9 & 0xc0) == 0) && ((0xff < lVar17 || (lVar17 < -0x80)))) {
LAB_140001cb3:
            *(longlong *)((longlong)alStack_68 + lVar5) = lVar17;
                    /* WARNING: Subroutine does not return */
            *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001cc9;
            __report_error("%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p.\n"
                           ,(ulonglong)uVar12,plVar19,uVar14);
          }
          puVar15 = puVar15 + 3;
          *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001d2e;
          mark_section_writable((ulonglong)plVar19,(ulonglong)(uVar9 & 0xc0),param_3,uVar14);
          *(byte *)plVar19 = (byte)lVar17;
        } while (puVar15 < puVar7);
        goto LAB_140001d40;
      }
    }
  }
  else if (*(uint *)_refptr___RUNTIME_PSEUDO_RELOC_LIST__ == 0) {
    uVar9 = *(uint *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 4);
    uVar14 = (ulonglong)(uVar9 | *(uint *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 8));
    if ((uVar9 | *(uint *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 8)) == 0) {
      piVar16 = (int *)(_refptr___RUNTIME_PSEUDO_RELOC_LIST__ + 0xc);
      goto LAB_140001bcd;
    }
    goto LAB_140001bda;
  }
  if (_refptr___RUNTIME_PSEUDO_RELOC_LIST_END__ <= piVar16) {
    maxSections = 0;
    return;
  }
  do {
    puVar15 = (uint *)(piVar16 + 1);
    iVar20 = *piVar16;
    piVar16 = piVar16 + 2;
    piVar18 = (int *)(puVar6 + *puVar15);
    iVar4 = *piVar18;
    *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001e66;
    mark_section_writable((ulonglong)piVar18,uVar14,param_3,param_4);
    *piVar18 = iVar20 + iVar4;
  } while (piVar16 < puVar7);
LAB_140001d40:
  if (0 < maxSections) {
    lVar17 = 0;
    iVar20 = 0;
    do {
      pDVar11 = (DWORD *)(the_secs + lVar17);
      flNewProtect = *pDVar11;
      if (flNewProtect != 0) {
        dwSize = *(SIZE_T *)(pDVar11 + 4);
        lpAddress = *(LPVOID *)(pDVar11 + 2);
        *(undefined8 *)((longlong)auStack_90 + lVar5) = 0x140001d7f;
        VirtualProtect(lpAddress,dwSize,flNewProtect,local_4c);
      }
      iVar20 = iVar20 + 1;
      lVar17 = lVar17 + 0x28;
    } while (iVar20 < maxSections);
  }
  return;
}

/* Function: __mingw_raise_matherr */
void __mingw_raise_matherr
               (undefined4 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  undefined4 local_38 [2];
  undefined8 local_30;
  undefined local_28 [16];
  undefined8 local_18;
  
  if (stUserMathErr != (code *)0x0) {
    local_28._8_8_ = param_4;
    local_28._0_8_ = param_3;
    local_18 = param_5;
    local_38[0] = param_1;
    local_30 = param_2;
    (*stUserMathErr)(local_38);
  }
  return;
}

/* Function: __mingw_setusermatherr */
void __mingw_setusermatherr(undefined8 param_1)

{
  stUserMathErr = param_1;
  __setusermatherr();
  return;
}

/* Function: __mingwthr_run_key_dtors.part.0 */
void __mingwthr_run_key_dtors_part_0(void)

{
  DWORD *pDVar1;
  DWORD DVar2;
  LPVOID pvVar3;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  for (pDVar1 = key_dtor_list; pDVar1 != (DWORD *)0x0; pDVar1 = *(DWORD **)(pDVar1 + 4)) {
    pvVar3 = TlsGetValue(*pDVar1);
    DVar2 = GetLastError();
    if ((pvVar3 != (LPVOID)0x0) && (DVar2 == 0)) {
      (**(code **)(pDVar1 + 2))(pvVar3);
    }
  }
                    /* WARNING: Could not recover jumptable at 0x000140002109. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
  return;
}

/* Function: __mingw_TLScallback */
undefined8 __mingw_TLScallback(undefined8 param_1,uint param_2)

{
  void *pvVar1;
  void *_Memory;
  
  if (param_2 == 2) {
    fpreset();
    return 1;
  }
  if (param_2 < 3) {
    if (param_2 == 0) {
      if (__mingwthr_cs_init != 0) {
        __mingwthr_run_key_dtors_part_0();
      }
      if (__mingwthr_cs_init == 1) {
        __mingwthr_cs_init = 1;
        _Memory = key_dtor_list;
        while (_Memory != (void *)0x0) {
          pvVar1 = *(void **)((longlong)_Memory + 0x10);
          free(_Memory);
          _Memory = pvVar1;
        }
        key_dtor_list = (void *)0x0;
        __mingwthr_cs_init = 0;
        DeleteCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
      }
    }
    else {
      if (__mingwthr_cs_init == 0) {
        InitializeCriticalSection((LPCRITICAL_SECTION)&__mingwthr_cs);
      }
      __mingwthr_cs_init = 1;
    }
  }
  else if ((param_2 == 3) && (__mingwthr_cs_init != 0)) {
    __mingwthr_run_key_dtors_part_0();
  }
  return 1;
}

/* Function: _ValidateImageBase */
BOOL __cdecl _ValidateImageBase(PBYTE pImageBase)

{
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (BOOL)(*(short *)((longlong)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x20b);
  }
  return 0;
}

/* Function: __mingw_GetSectionForAddress */
IMAGE_SECTION_HEADER * __mingw_GetSectionForAddress(longlong param_1)

{
  IMAGE_SECTION_HEADER *pIVar1;
  IMAGE_SECTION_HEADER *pIVar2;
  int *piVar3;
  
  if (((*(short *)_refptr___ImageBase == 0x5a4d) &&
      (piVar3 = (int *)(_refptr___ImageBase + *(int *)(_refptr___ImageBase + 0x3c)),
      *piVar3 == 0x4550)) && (*(short *)(piVar3 + 6) == 0x20b)) {
    pIVar2 = (IMAGE_SECTION_HEADER *)((longlong)piVar3 + (ulonglong)*(ushort *)(piVar3 + 5) + 0x18);
    if (*(ushort *)((longlong)piVar3 + 6) != 0) {
      pIVar1 = pIVar2 + (ulonglong)(*(ushort *)((longlong)piVar3 + 6) - 1) + 1;
      do {
        if (((ulonglong)(uint)pIVar2->VirtualAddress <=
             (ulonglong)(param_1 - (longlong)_refptr___ImageBase)) &&
           ((ulonglong)(param_1 - (longlong)_refptr___ImageBase) <
            (ulonglong)(pIVar2->VirtualAddress + (pIVar2->Misc).PhysicalAddress))) {
          return pIVar2;
        }
        pIVar2 = pIVar2 + 1;
      } while (pIVar2 != pIVar1);
    }
    return (IMAGE_SECTION_HEADER *)0x0;
  }
  return (IMAGE_SECTION_HEADER *)0x0;
}

/* Function: __mingw_GetSectionCount */
undefined2 __mingw_GetSectionCount(void)

{
  int *piVar1;
  
  if (((*(short *)_refptr___ImageBase == 0x5a4d) &&
      (piVar1 = (int *)(_refptr___ImageBase + *(int *)(_refptr___ImageBase + 0x3c)),
      *piVar1 == 0x4550)) && (*(short *)(piVar1 + 6) == 0x20b)) {
    return *(undefined2 *)((longlong)piVar1 + 6);
  }
  return 0;
}

/* Function: _GetPEImageBase */
IMAGE_DOS_HEADER * _GetPEImageBase(void)

{
  IMAGE_DOS_HEADER *pIVar1;
  
  if ((*(short *)_refptr___ImageBase == 0x5a4d) &&
     (*(int *)(_refptr___ImageBase + *(int *)(_refptr___ImageBase + 0x3c)) == 0x4550)) {
    pIVar1 = (IMAGE_DOS_HEADER *)0x0;
    if (*(short *)((longlong)(_refptr___ImageBase + *(int *)(_refptr___ImageBase + 0x3c)) + 0x18) ==
        0x20b) {
      pIVar1 = (IMAGE_DOS_HEADER *)_refptr___ImageBase;
    }
    return pIVar1;
  }
  return (IMAGE_DOS_HEADER *)0x0;
}

/* Function: ___chkstk_ms */
/* WARNING: This is an inlined function */

ulonglong ___chkstk_ms(void)

{
  ulonglong in_RAX;
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 local_res8 [4];
  ulonglong uStack_10;
  
  puVar2 = local_res8;
  uVar1 = in_RAX;
  if (0xfff < in_RAX) {
    do {
      puVar2 = puVar2 + -0x200;
      *puVar2 = *puVar2;
      uVar1 = uVar1 - 0x1000;
    } while (0x1000 < uVar1);
  }
  uStack_10 = in_RAX;
  *(undefined8 *)((longlong)puVar2 - uVar1) = *(undefined8 *)((longlong)puVar2 - uVar1);
  return uStack_10;
}

/* Function: log */
double __cdecl log(double _X)

{
  double dVar1;
  uint uVar2;
  int *piVar3;
  uint uVar4;
  float10 local_38;
  float10 local_28 [2];
  
  uVar2 = (uint)((ulonglong)_X >> 0x20);
  uVar4 = uVar2 & 0x7ff00000;
  uVar2 = uVar2 & 0xfffff | SUB84(_X,0);
  if ((uVar2 | uVar4) == 0) {
    piVar3 = _errno();
    dVar1 = DAT_1400043d8;
    *piVar3 = 0x22;
    __mingw_raise_matherr(3,&_rdata,_X,0,dVar1);
    return dVar1;
  }
  if (uVar4 == 0x7ff00000) {
    if (uVar2 != 0) {
      return _X;
    }
    if (-1 < (longlong)_X) {
      return DAT_1400043e8;
    }
  }
  else if (-1 < (longlong)_X) {
    local_38 = (float10)_X;
    __logl_internal(local_28,&local_38);
    return (double)local_28[0];
  }
  piVar3 = _errno();
  dVar1 = DAT_1400043e0;
  *piVar3 = 0x21;
  __mingw_raise_matherr(1,&_rdata,_X,0,dVar1);
  return dVar1;
}

/* Function: __logl_internal */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

float10 * __logl_internal(float10 *param_1,float10 *param_2)

{
  float10 fVar1;
  float10 fVar2;
  float10 fVar3;
  float10 fVar4;
  
  fVar1 = *param_2;
  fVar3 = fVar1 - (float10)_one;
  fVar4 = ABS(fVar3);
  fVar2 = (float10)_limit;
  if ((byte)(fVar4 < fVar2 | (byte)((ushort)((ushort)(NAN(fVar4) || NAN(fVar2)) << 10) >> 8) |
            (byte)((ushort)((ushort)(fVar4 == fVar2) << 0xe) >> 8)) != 0) {
    *(undefined8 *)((longlong)param_1 + 8) = 0;
    *param_1 = (float10)0.6931471805599453 * (fVar3 + (float10)1);
    return param_1;
  }
  *(undefined8 *)((longlong)param_1 + 8) = 0;
  *param_1 = (float10)0.6931471805599453 * fVar1;
  return param_1;
}

/* Function: vfprintf */
int __cdecl vfprintf(FILE *_File,char *_Format,va_list _ArgList)

{
  int iVar1;
  
  iVar1 = __stdio_common_vfprintf(0,_File,_Format,0,_ArgList);
  return iVar1;
}

/* Function: fprintf */
int __cdecl fprintf(FILE *_File,char *_Format,...)

{
  int iVar1;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 local_res18;
  undefined8 local_res20;
  
  local_res18 = in_R8;
  local_res20 = in_R9;
  iVar1 = __stdio_common_vfprintf(0,_File,_Format,0,&local_res18);
  return iVar1;
}

/* Function: _get_output_format */
uint __cdecl _get_output_format(void)

{
  return 0;
}

/* Function: __getmainargs */
undefined8
__getmainargs(undefined4 *param_1,undefined8 *param_2,undefined8 *param_3,int param_4,
             undefined4 *param_5)

{
  undefined4 *puVar1;
  undefined8 *puVar2;
  
  _initialize_narrow_environment();
  _configure_narrow_argv(2 - (uint)(param_4 == 0));
  puVar1 = (undefined4 *)__p___argc();
  *param_1 = *puVar1;
  puVar2 = (undefined8 *)__p___argv();
  *param_2 = *puVar2;
  puVar2 = (undefined8 *)__p__environ();
  *param_3 = *puVar2;
  if (param_5 != (undefined4 *)0x0) {
    _set_new_mode(*param_5);
  }
  return 0;
}

/* Function: _onexit */
_onexit_t __cdecl _onexit(_onexit_t _Func)

{
  int iVar1;
  _onexit_t p_Var2;
  
  iVar1 = _crt_atexit();
  p_Var2 = (_onexit_t)0x0;
  if (iVar1 == 0) {
    p_Var2 = _Func;
  }
  return p_Var2;
}

/* Function: _amsg_exit */
void __cdecl _amsg_exit(int param_1)

{
  FILE *_File;
  
  _File = (FILE *)__acrt_iob_func(2);
  fprintf(_File,"runtime error %d\n",(ulonglong)(uint)param_1);
                    /* WARNING: Subroutine does not return */
  _exit(0xff);
}

/* Function: __daylight */
int * __cdecl __daylight(void)

{
  int *piVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002b50. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  piVar1 = __daylight();
  return piVar1;
}

/* Function: __timezone */
long * __cdecl __timezone(void)

{
  long *plVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002b58. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  plVar1 = __timezone();
  return plVar1;
}

/* Function: __tzname */
char ** __cdecl __tzname(void)

{
  char **ppcVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002b60. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  ppcVar1 = __tzname();
  return ppcVar1;
}

/* Function: strlen */
size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002b70. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar1 = strlen(_Str);
  return sVar1;
}

/* Function: strncmp */
int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002b78. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = strncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}

/* Function: __acrt_iob_func */
void __acrt_iob_func(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002b80. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __acrt_iob_func();
  return;
}

/* Function: __p__commode */
void __p__commode(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002b88. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__commode();
  return;
}

/* Function: __p__fmode */
void __p__fmode(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002b90. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__fmode();
  return;
}

/* Function: __stdio_common_vfprintf */
void __stdio_common_vfprintf(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002b98. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __stdio_common_vfprintf();
  return;
}

/* Function: __stdio_common_vfwprintf */
void __stdio_common_vfwprintf(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002ba0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __stdio_common_vfwprintf();
  return;
}

/* Function: fwrite */
size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002ba8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  sVar1 = fwrite(_Str,_Size,_Count,_File);
  return sVar1;
}

/* Function: __p___argc */
void __p___argc(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bb0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p___argc();
  return;
}

/* Function: __p___argv */
void __p___argv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bb8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p___argv();
  return;
}

/* Function: __p___wargv */
void __p___wargv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bc0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p___wargv();
  return;
}

/* Function: _cexit */
void __cdecl _cexit(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bc8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _cexit();
  return;
}

/* Function: _configure_narrow_argv */
void _configure_narrow_argv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bd0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _configure_narrow_argv();
  return;
}

/* Function: _configure_wide_argv */
void _configure_wide_argv(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bd8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _configure_wide_argv();
  return;
}

/* Function: _crt_atexit */
void _crt_atexit(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002be8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _crt_atexit();
  return;
}

/* Function: _errno */
int * __cdecl _errno(void)

{
  int *piVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002bf0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  piVar1 = _errno();
  return piVar1;
}

/* Function: _exit */
void __cdecl _exit(int _Code)

{
                    /* WARNING: Could not recover jumptable at 0x000140002bf8. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  _exit(_Code);
  return;
}

/* Function: _initialize_narrow_environment */
void _initialize_narrow_environment(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c00. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initialize_narrow_environment();
  return;
}

/* Function: _initialize_wide_environment */
void _initialize_wide_environment(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c08. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initialize_wide_environment();
  return;
}

/* Function: _initterm */
void _initterm(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c10. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _initterm();
  return;
}

/* Function: __set_app_type */
void __set_app_type(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c18. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _set_app_type();
  return;
}

/* Function: _set_invalid_parameter_handler */
_invalid_parameter_handler __cdecl
_set_invalid_parameter_handler(_invalid_parameter_handler _Handler)

{
  _invalid_parameter_handler p_Var1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002c20. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  p_Var1 = _set_invalid_parameter_handler(_Handler);
  return p_Var1;
}

/* Function: abort */
void __cdecl abort(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c28. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  abort();
  return;
}

/* Function: exit */
void __cdecl exit(int _Code)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c30. Too many branches */
                    /* WARNING: Subroutine does not return */
                    /* WARNING: Treating indirect jump as call */
  exit(_Code);
  return;
}

/* Function: signal */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void signal(int param_1)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c38. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  signal(param_1);
  return;
}

/* Function: system */
int __cdecl system(char *_Command)

{
  int iVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002c40. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = system(_Command);
  return iVar1;
}

/* Function: __C_specific_handler */
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

EXCEPTION_DISPOSITION
__C_specific_handler
          (_EXCEPTION_RECORD *ExceptionRecord,void *EstablisherFrame,_CONTEXT *ContextRecord,
          _DISPATCHER_CONTEXT *DispatcherContext)

{
  EXCEPTION_DISPOSITION EVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002c50. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EVar1 = __C_specific_handler(ExceptionRecord,EstablisherFrame,ContextRecord,DispatcherContext);
  return EVar1;
}

/* Function: memcpy */
void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002c58. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}

/* Function: __setusermatherr */
void __setusermatherr(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c60. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __setusermatherr();
  return;
}

/* Function: _set_new_mode */
void _set_new_mode(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c70. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  _set_new_mode();
  return;
}

/* Function: calloc */
void * __cdecl calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002c78. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = calloc(_Count,_Size);
  return pvVar1;
}

/* Function: free */
void __cdecl free(void *_Memory)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c80. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  free(_Memory);
  return;
}

/* Function: malloc */
void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002c88. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = malloc(_Size);
  return pvVar1;
}

/* Function: __p__environ */
void __p__environ(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c90. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__environ();
  return;
}

/* Function: __p__wenviron */
void __p__wenviron(void)

{
                    /* WARNING: Could not recover jumptable at 0x000140002c98. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  __p__wenviron();
  return;
}

/* Function: VirtualQuery */
SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002ca0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}

/* Function: VirtualProtect */
BOOL __stdcall
VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect)

{
  BOOL BVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002ca8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  BVar1 = VirtualProtect(lpAddress,dwSize,flNewProtect,lpflOldProtect);
  return BVar1;
}

/* Function: TlsGetValue */
LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)

{
  LPVOID pvVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002cb0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}

/* Function: Sleep */
void __stdcall Sleep(DWORD dwMilliseconds)

{
                    /* WARNING: Could not recover jumptable at 0x000140002cb8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  Sleep(dwMilliseconds);
  return;
}

/* Function: SetUnhandledExceptionFilter */
LPTOP_LEVEL_EXCEPTION_FILTER __stdcall
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)

{
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002cc0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pPVar1 = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return pPVar1;
}

/* Function: LeaveCriticalSection */
void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140002cc8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  LeaveCriticalSection(lpCriticalSection);
  return;
}

/* Function: InitializeCriticalSection */
void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140002cd0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  InitializeCriticalSection(lpCriticalSection);
  return;
}

/* Function: GetLastError */
DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    /* WARNING: Could not recover jumptable at 0x000140002cd8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  DVar1 = GetLastError();
  return DVar1;
}

/* Function: EnterCriticalSection */
void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140002ce0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  EnterCriticalSection(lpCriticalSection);
  return;
}

/* Function: DeleteCriticalSection */
void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    /* WARNING: Could not recover jumptable at 0x000140002ce8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  DeleteCriticalSection(lpCriticalSection);
  return;
}

;