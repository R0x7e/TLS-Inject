import pefile
pe = pefile.PE('target_injected.exe')
print(pe.dump_info())
