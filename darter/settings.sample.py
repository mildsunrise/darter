# These depend on how the runtime was compiled / what arch
# Adjust them as appropriate

DEBUG = False
PRECOMPILED_RUNTIME = True # ??? verify
PRODUCT = True
HASH_IN_OBJECT_HEADER = True
PTRBITS = 32
RAW_INSTANCE_SIZE_IN_WORDS = 1  # sizeof(RawInstance) / wordSize
