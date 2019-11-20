import re

from ..constants import kClassId, kkClassId, kStubCodeList, kCachedICDataArrayCount, kCachedDescriptorCount

class_cids = [ n for n in range(kkClassId['Class'], kkClassId['Instance']) if n != kkClassId['Error'] ]
class_cids += [ kkClassId['Dynamic'], kkClassId['Void'] ]

make_base_entries = lambda includes_code: [
    ("Object::null()", "Null", "null"),
    ("Object::sentinel().raw()", "Null", "sentinel"),
    ("Object::transition_sentinel().raw()", "Null", "transition_sentinel"),
    ("Object::empty_array().raw()", "Array", "<empty_array>"),
    ("Object::zero_array().raw()", "Array", "<zero_array>"),
    ("Object::dynamic_type().raw()", "Type", "<dynamic type>"),
    ("Object::void_type().raw()", "Type", "<void type>"),
    ("Object::empty_type_arguments().raw()", "TypeArguments", "[]"),
    ("Bool::True().raw()", "bool", "true"),
    ("Bool::False().raw()", "bool", "false"),
    ("Object::extractor_parameter_types().raw()", "Array", "<extractor parameter types>"),
    ("Object::extractor_parameter_names().raw()", "Array", "<extractor parameter names>"),
    ("Object::empty_context_scope().raw()", "ContextScope", "<empty>"),
    ("Object::empty_descriptors().raw()", "PcDescriptors", "<empty>"),
    ("Object::empty_var_descriptors().raw()", "LocalVarDescriptors", "<empty>"),
    ("Object::empty_exception_handlers().raw()", "ExceptionHandlers", "<empty>"),
    ("Object::implicit_getter_bytecode().raw()", "Bytecode", "<implicit getter>"),
    ("Object::implicit_setter_bytecode().raw()", "Bytecode", "<implicit setter>"),
    ("Object::implicit_static_getter_bytecode().raw()", "Bytecode", "<implicit static getter>"),
    ("Object::method_extractor_bytecode().raw()", "Bytecode", "<method extractor>"),
    ("Object::invoke_closure_bytecode().raw()", "Bytecode", "<invoke closure>"),
    ("Object::invoke_field_bytecode().raw()", "Bytecode", "<invoke field>"),
    ("Object::nsm_dispatcher_bytecode().raw()", "Bytecode", "<nsm dispatcher>"),
    ("Object::dynamic_invocation_forwarder_bytecode().raw()", "Bytecode", "<dyn forwarder>"),
    *( ("ArgumentsDescriptor::cached_args_descriptors_[i]", "ArgumentsDescriptor", "<cached arguments descriptor {}>".format(i)) for i in range(kCachedDescriptorCount) ),
    *( ("ICData::cached_icdata_arrays_[i]", "Array", "<empty icdata entries {}>".format(i)) for i in range(kCachedICDataArrayCount) ),
    *( ("class_table()->At(cid)", "Class", kClassId[cid]) for cid in class_cids ), # Adapted
    *( ( ("StubCode::EntryAt(i).raw()", "Code", "<stub code {}>".format(i)) for i in kStubCodeList ) if not includes_code else [] ),
]

def make_base_objects(includes_code):
    tmp_cluster = { 'handler': 'BaseObject', 'cid': 'BaseObject' } 
    class BaseRef:
        def __init__(self, ref, entry):
            self.ref = ref
            self.cluster = tmp_cluster
            self.x = { 'type': entry[1], 'value': entry[2] }
            self.prop = ''
    entries = make_base_entries(includes_code)
    base = { i+1: BaseRef(i+1, entry) for i, entry in enumerate(entries) }
    base['next'] = len(entries) + 1
    return base
