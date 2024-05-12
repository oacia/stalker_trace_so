# -*- coding:utf-8 -*-
import os
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
from idaapi import get_imagebase
import ida_nalt
import idautils
import idc
import random

class stalker_trace_so(plugin_t):
    flags = PLUGIN_PROC
    comment = "stalker_trace_so"
    help = ""
    wanted_name = "stalker_trace_so"
    wanted_hotkey = ""

    def init(self):
        print("stalker_trace_so plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):

        func_addr = []
        func_name = []
        so_base = get_imagebase()
        for func_ea in idautils.Functions():
            # thumb mode
            if idc.get_sreg(func_ea, "T"):
                func_addr.append(hex(func_ea + 1-so_base))
            else:
                func_addr.append(hex(func_ea-so_base))
            func_name.append('"{}"'.format(idc.get_func_name(func_ea)))
        template_js = 'var func_addr = [{}];\nvar func_name = [{}];\nvar so_name = "{}";\n/*\n    @param print_stack\n    是否输出堆栈信息,默认为false\n*/\nvar print_stack = false;\n/*\n    @param print_stack_mode\n    - FUZZY: 打印尽可能多的堆栈信息\n    - ACCURATE: 打印尽可能准确的堆栈信息\n    - MANUAL: 如果打印堆栈报错退出, 使用该选项手动打印地址\n*/\n\nvar print_stack_mode = "FUZZY";\nfunction addr_in_so(addr){{\n    var process_Obj_Module_Arr = Process.enumerateModules();\n    for(var i = 0; i < process_Obj_Module_Arr.length; i++) {{\n        if(addr>process_Obj_Module_Arr[i].base && addr<process_Obj_Module_Arr[i].base.add(process_Obj_Module_Arr[i].size)){{\n            console.log(addr.toString(16),"is in",process_Obj_Module_Arr[i].name,"offset: 0x"+(addr-process_Obj_Module_Arr[i].base).toString(16));\n        }}\n    }}\n}}\nfunction hook_dlopen() {{\n    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),\n        {{\n            onEnter: function (args) {{\n                var pathptr = args[0];\n                if (pathptr !== undefined && pathptr != null) {{\n                    var path = ptr(pathptr).readCString();\n                    //console.log(path);\n                    if (path.indexOf(so_name) >= 0) {{\n                        this.is_can_hook = true;\n                    }}\n                }}\n            }},\n            onLeave: function (retval) {{\n                if (this.is_can_hook) {{\n                    //you can do any thing before stalker trace so\n                    \n                    trace_so();\n                }}\n            }}\n        }}\n    );\n}}\n\nfunction trace_so(){{\n    var times = 1;\n    var module = Process.getModuleByName(so_name);\n    var pid = Process.getCurrentThreadId();\n    console.log("start Stalker!");\n    Stalker.exclude({{\n        "base": Process.getModuleByName("libc.so").base,\n        "size": Process.getModuleByName("libc.so").size\n    }})\n    Stalker.follow(pid,{{\n        events:{{\n            call:false,\n            ret:false,\n            exec:false,\n            block:false,\n            compile:false\n        }},\n        onReceive:function(events){{\n        }},\n        transform: function (iterator) {{\n            var instruction = iterator.next();\n            do{{\n                if (func_addr.indexOf(instruction.address - module.base) !== -1) {{\n                    console.log("call" + times + ":" + func_name[func_addr.indexOf(instruction.address - module.base)])\n                    times = times + 1\n                    if (print_stack) {{\n                        if (print_stack_mode === "FUZZY") {{\n                            iterator.putCallout((context) => {{\n                                console.log("backtrace:\\n"+Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join(\'\\n\'));\n                                console.log(\'---------------------\')\n                            }});\n                        }}\n                        else if (print_stack_mode === "ACCURATE") {{\n                            iterator.putCallout((context) => {{\n                                console.log("backtrace:\\n"+Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(\'\\n\'));\n                                console.log(\'---------------------\')\n                            }})\n                        }}\n\n                        else if (print_stack_mode === "MANUAL") {{\n                            iterator.putCallout((context) => {{\n                                console.log("backtrace:")\n                                Thread.backtrace(context, Backtracer.FUZZY).map(addr_in_so);\n                                console.log(\'---------------------\')\n                            }})\n                        }}\n                    }}\n                }}\n                iterator.keep();\n            }} while ((instruction = iterator.next()) !== null);\n        }},\n\n        onCallSummary:function(summary){{\n\n        }}\n    }});\n    console.log("Stalker end!");\n}}\n\nsetImmediate(hook_dlopen,0);\n'
        so_path, so_name = os.path.split(ida_nalt.get_input_file_path())
        hook_code = template_js.format(', '.join(func_addr), ', '.join(func_name), so_name)
        r = [random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5)]
        script_name = "trace_" + so_name.split(".")[0] +'_'+''.join(r) + ".js"
        save_path = os.path.join(so_path, script_name)
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(hook_code)

        print("usage:")
        print(f'frida -U -l "{save_path}" -f [package name]')

    def term(self):
        pass


def PLUGIN_ENTRY():
    return stalker_trace_so()
