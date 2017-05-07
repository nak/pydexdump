import os
import shutil
import sys
import tempfile
import zipfile
from abc import ABCMeta
from dexdump import junit3
from . import ByteStream


class DexParser(object):

    class FormatException(Exception):
        pass

    class DexMagic(object):
        """
        Magic numbers for validation of dex file
        """
        SIZE_MAGIC_DEX = 3
        SIZE_MAGIC_VERSION = 3

        EXPECTED_DEX = bytes([0x64, 0x65, 0x78]) if sys.version_info >= (3,) else 'dex'
        EXPECTED_VERSION = bytes([0x30, 0x33, 0x35]) if sys.version_info >= (3,) else '035'

        def __init__(self, bytestream):
            self._dex = bytestream.read_bytes(DexParser.DexMagic.SIZE_MAGIC_DEX)
            self._newline = bytestream.read_byte()
            self._version = bytestream.read_bytes(DexParser.DexMagic.SIZE_MAGIC_VERSION)
            self._zero = bytestream.read_byte()

        def validate(self):
            return (self._dex == DexParser.DexMagic.EXPECTED_DEX and
                    self._newline == 0x0A and
                    self._version == DexParser.DexMagic.EXPECTED_VERSION and
                    self._zero == 0x00)

    class Header(object):
        """
        class holding header information from a dex file
        """
        SIZE_SIGNATURE = 20
        EXPECTED_ENDIAN_TAG = 0x12345678

        def __init__(self, bytestream):
            self._magic = DexParser.DexMagic(bytestream)
            self._checksum = bytestream.read_int()
            self._signature = bytestream.read_bytes(DexParser.Header.SIZE_SIGNATURE)
            self._file_size, self._header_size, self._endian_tag, self._link_size, self._link_offset, \
              self._map_offset = bytestream.read_ints(6)
            self._size_and_offset = {}
            for clazz in [DexParser.StringIdItem, DexParser.TypeIdItem, DexParser.ProtoIdItem,
                          DexParser.FieldIdItem, DexParser.MethodIdItem, DexParser.ClassDefItem,
                          DexParser.ClassDefData]:
                # define for each data class the size and offset of where that class's data is stored
                size, offset = bytestream.read_ints(2)
                self._size_and_offset[clazz] = (size, offset)

        def size_and_offset(self, clazz):
            return self._size_and_offset.get(clazz)

        def validate(self):
            """
            :raises: `DexFormatException` if data read from dex file fails validation checks
            """
            if not self._magic.validate():
                raise DexParser.FormatException("Invalid dex magic in dex file")
            if self._endian_tag != DexParser.Header.EXPECTED_ENDIAN_TAG:
                raise DexParser.FormatException("Invalid endian-ness/tag in dex file")

    ######################################################
    # Various data classes for holding dex-item data
    # These basically pull byte data out of the dex file to be interpreted into various classes of data
    #

    class Item(object):
        """
        base class for all data items
        """
        FORMAT = "*"

        __metaclass__ = ABCMeta
        _count = 0

        def __init__(self, bytestream):
            self._bytestream = bytestream

        @classmethod
        def get(cls, bytestream, count):
            import struct
            if cls.FORMAT[0] == '*':
                # have variant-sized or un-type-able objects
                return [cls(bytestream) for _ in range(count)]
            else:
                if sys.version_info >= (3,):
                    items = struct.iter_unpack("<" + cls.FORMAT, bytestream.read(
                        count * struct.calcsize("<" + cls.FORMAT)))
                    return [cls(bytestream, item) for item in items]
                else:
                    return [cls(bytestream,
                                struct.unpack("<" + cls.FORMAT, bytestream.read(struct.calcsize("<" + cls.FORMAT))))
                            for _ in range(count)]

    class Annotation(Item):
        FORMAT = "ii"

        def __init__(self, bytestream, vals):
            super(DexParser.Annotation, self).__init__(bytestream)
            self.index, self.annotations_offset = vals

    class AnnotationItem(Item):
        FORMAT = "*b*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationItem, self).__init__(bytestream)
            self.visibility = bytestream.read_byte()
            self.encoded_annotation = bytestream.parse_one_item(None, DexParser.EncodedAnnotation)

    class AnnotationOffsetItem(Item):
        FORMAT = "i"

        def __init__(self, bytestream, vals):
            super(DexParser.AnnotationOffsetItem, self).__init__(bytestream)
            self.annotation_offset = vals[0]

    class AnnotationSetItem(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationSetItem, self).__init__(bytestream)
            size = bytestream.read_int()
            self.entries = self._bytestream.parse_items(size, None, DexParser.AnnotationOffsetItem)

        def __iter__(self):
            for item in self.entries:
                yield item

    class AnnotationElement(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationElement, self).__init__(bytestream)
            self.name_index = bytestream.read_leb128()
            self.value = bytestream.parse_one_item(None, DexParser.EncodedValue)

    class AnnotationsDirectoryItem(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.AnnotationsDirectoryItem, self).__init__(bytestream)
            self.class_annotations_offset, \
            field_size, \
            annotated_method_size, \
            annotated_parameter_size = bytestream.read_ints(4)
            self.field_annotations = DexParser.Annotation.get(bytestream, field_size)
            self.method_annotations = DexParser.Annotation.get(bytestream, annotated_method_size)
            self.parameter_annotations = DexParser.Annotation.get(bytestream, annotated_parameter_size)

        def get_methods_with_annotation(self, target_descriptor, method_ids):
            """
            :param target_descriptor: annotation of interest, in descriptor format
            :param method_ids: list of MethodIdItems for querying name
            :return: all vritual methods int his directory of that ar annotated with given descriptor
            """
            results = []
            for annotation in self.method_annotations:
                if annotation.annotations_offset == 0:
                    continue
                entries = self._bytestream.parse_one_item(annotation.annotations_offset, DexParser.AnnotationSetItem)
                for entry in entries:
                    item = self._bytestream.parse_one_item(entry.annotation_offset, DexParser.AnnotationItem)
                    type_id = self._type_ids[item.encoded_annotation.type_index]
                    string_id = self._string_ids[type_id.descriptor_index]
                    my_descriptor = self._bytestream.parse_descriptor(string_id)
                    if target_descriptor == my_descriptor:
                        method_id = method_ids[annotation.index]
                        method_descriptor = self._bytestream.parse_method_name(method_id)
                        results.append(method_descriptor)
                        break
            return set(results)

    class ClassDefItem(Item):
        FORMAT = "iiiiiiii"

        def __init__(self, bytestream, ints):
            super(DexParser.ClassDefItem, self).__init__(bytestream)
            self.class_index, self.access_flags, self.super_class_index, self.interfaces_offset, \
            self.source_file_index, self.annotations_offset, self.class_data_offset, self.static_values_offset = ints
            self._super_type = None
            self._descriptor = None
            self._super_descriptor = None
            self._type_index = self.class_index

        @property
        def descriptor(self):
            if not self._descriptor:
                type_id = self._type_ids[self.class_index]
                string_id = self._string_ids[type_id.descriptor_index]
                self._descriptor = self._bytestream.parse_descriptor(string_id)
            return self._descriptor

        def super_descriptor(self):
            """
            :return: the string descriptor (cached) of the super class of this class def
            """
            if not self._super_descriptor:
                desc_index = self.super_type().descriptor_index
                string_id = self._string_ids[desc_index]
                self._super_descriptor = self._bytestream.parse_descriptor(string_id)
            return self._super_descriptor

        def super_type(self):
            """
            :return: type TypeIdItem of the super class or None if no inheritance
            """
            if self.super_class_index < 0:
                return None
            return self._type_ids[self.super_class_index]

        def has_direct_super_class(self, descriptors):
            """
            :param descriptors: list of descriptor-style class names
            :return: whether this class inherits from one of the classes defined by the given descriptors
            """
            if self.super_class_index < 0:
                return False
            desc = self.super_descriptor()
            return desc in descriptors

    class ClassDefData(Item):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.ClassDefData, self).__init__(bytestream)
            static_fields_size = bytestream.read_leb128()
            instance_fields_size = bytestream.read_leb128()
            direct_methods_size = bytestream.read_leb128()
            virtual_methods_size = bytestream.read_leb128()
            self.static_fields = bytestream.parse_items(static_fields_size, None, DexParser.EncodedField)
            self.instance_fields = bytestream.parse_items(instance_fields_size, None, DexParser.EncodedField)
            self.direct_methods = bytestream.parse_items(direct_methods_size, None, DexParser.EncodedMethod)
            self.virtual_methods = bytestream.parse_items(virtual_methods_size, None, DexParser.EncodedMethod)

    class EncodedAnnotation(Item):
        FORMAT = "*i*"

        def __init__(self, bytestream):
            super(DexParser.EncodedAnnotation, self).__init__(bytestream)
            self.type_index = bytestream.read_leb128()
            size = bytestream.read_leb128()
            self.elements = bytestream.parse_items(size, None, DexParser.AnnotationElement)

    class EncodedItem(Item):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.EncodedItem, self).__init__(bytestream)
            self.index_diff = bytestream.read_leb128()
            self.access_flags = bytestream.read_leb128()

    EncodedField = EncodedItem

    class EncodedMethod(EncodedItem):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.EncodedMethod, self).__init__(bytestream)
            self.code_offset = bytestream.read_leb128()

        def method_name(self, method_ids):
            method_id = method_ids[self.index_diff]
            return self._bytestream.parse_method_name(method_id)

    class EncodedArray(Item):
        FORMAT = "*"

        def __init__(self, bytestream):
            super(DexParser.EncodedArray, self).__init__(bytestream)
            self.size = bytestream.read_leb128()
            self.value = bytestream.parse_items(self.size, None, DexParser.EncodedValue)

    class EncodedValue(Item):
        FORMAT = "*"

        VALUE_BYTE = 0x00
        VALUE_SHORT = 0x02
        VALUE_CHAR = 0x03
        VALUE_INT = 0x04
        VALUE_LONG = 0x06
        VALUE_FLOAT = 0x10
        VALUE_DOUBLE = 0x11
        VALUE_STRING = 0x17
        VALUE_TYPE = 0x18
        VALUE_FIELD = 0x19
        VALUE_METHOD = 0x1A
        VALUE_ENUM = 0x1B
        VALUE_ARRAY = 0x1C
        VALUE_ANNOTATION = 0x1D
        VALUE_NULL = 0x1E
        VALUE_BOOLEAN = 0x1F

        def __init__(self, bytestream):
            super(DexParser.EncodedValue, self).__init__(bytestream)
            arg_and_type = bytestream.read_byte()
            value_arg = arg_and_type >> 5
            value_type = arg_and_type and 0x1F

            if value_type not in [getattr(self, name) for name in dir(self) if name.startswith("VALUE_")]:
                raise Exception("Value type invalid: %s" % value_type)
            if value_type <= DexParser.EncodedValue.VALUE_ENUM:
                self._value = bytestream.read_bytes(value_arg + 1)
            elif value_type == DexParser.EncodedValue.VALUE_ARRAY:
                size = self._bytestream.read(1)[0]
                self._value = bytestream.parse_items(size, None, DexParser.EncodedArray)
            elif value_type == DexParser.EncodedValue.VALUE_ANNOTATION:
                self._value = bytestream.parse_one_item(None, DexParser.EncodedAnnotation)
            elif value_type == DexParser.EncodedValue.VALUE_NULL:
                self._value = bytes([])
            elif value_type == DexParser.EncodedValue.VALUE_BOOLEAN:
                self._value = bytestream.read_bytes(value_arg)

    class FieldIdItem(Item):
        FORMAT = "ssi"

        def __init__(self, bytestream, vals):
            super(DexParser.FieldIdItem, self).__init__(bytestream)
            self.class_index, \
            self.type_index, \
            self.name_index = vals

    class MethodIdItem(Item):
        FORMAT = "hhi"

        def __init__(self, bytestream, vals):
            super(DexParser.MethodIdItem, self).__init__(bytestream)
            self.class_index, \
            self.proto_index, \
            self.name_index = vals

    class ProtoIdItem(Item):
        FORMAT = "iii"

        def __init__(self, bytestream, ints):
            super(DexParser.ProtoIdItem, self).__init__(bytestream)
            self.shorty_index, \
            self.return_type_index, \
            self.parameters_offset = ints

    class StringIdItem(Item):
        FORMAT = "i"

        def __init__(self, bytestream, offset):
            super(DexParser.StringIdItem, self).__init__(bytestream)
            self.data_offset = offset[0]

    class TypeIdItem(Item):
        FORMAT = "i"

        def __init__(self, bytestream, index):
            super(DexParser.TypeIdItem, self).__init__(bytestream)
            self.descriptor_index = index[0]

    #
    ##########################################################

    @staticmethod
    def parse(apk_file_name):
        """
        parse all dex files for a given apk
        :param apk_file_name: path to apk to parse
        :return: all test method names for JUnit3 and JUnit4 style tests
        """
        tempd = tempfile.mkdtemp()
        tests = []
        with zipfile.ZipFile(apk_file_name, mode="r") as zf:
            for item in [it for it in zf.filelist if it.filename.endswith('.dex')]:
                path = os.path.join(tempd, item.filename)
                zf.extract(item, tempd)
                parser = DexParser(path)
                tests += list(parser.find_junit3_tests()) + list(parser.find_junit4_tests())
        shutil.rmtree(tempd)
        return tests

    def __init__(self, file_name):
        self._bytestream = ByteStream(file_name)
        self._headers = DexParser.Header(self._bytestream)
        self._headers.validate()
        self._ids = {}
        for clazz in [DexParser.StringIdItem, DexParser.TypeIdItem, DexParser.ProtoIdItem,
                      DexParser.FieldIdItem, DexParser.MethodIdItem, DexParser.ClassDefItem]:
            size, offset = self._headers.size_and_offset(clazz)
            self._ids[clazz] = self._bytestream.parse_items(size, offset, clazz)
            if clazz == DexParser.TypeIdItem:
                DexParser.Item._type_ids = self._ids[clazz]
            elif clazz == DexParser.StringIdItem:
                DexParser.Item._string_ids = self._ids[clazz]

    def find_classes_directly_inherited_from(self, descriptors):
        """
        :param descriptors: descriptor-style list of class names
        :return: all classes that are directly inherited form one of the classes described by the descriptors
        """
        matching_classes = []
        fixed_set = set(descriptors)
        for clazz in [c for c in self._ids[DexParser.ClassDefItem] if c.has_direct_super_class(fixed_set)]:
            type_id = self._ids[DexParser.TypeIdItem][clazz.class_index]
            matching_classes.append(clazz)
            string_id = self._ids[DexParser.StringIdItem][type_id.descriptor_index]
            descriptors.append(self._bytestream.parse_descriptor(string_id))
        return matching_classes

    def find_method_names(self, class_def):
        """
        :param class_def: `DexParser.ClassDefItem` from which to find names
        :return: all method names for a given class def
        """
        class_data = self._bytestream.parse_one_item(class_def.class_data_offset, DexParser.ClassDefData)
        return [m.method_name(self._ids[DexParser.MethodIdItem]) for m in class_data.virtual_methods]

    @staticmethod
    def _descriptor2name(name):
        """
        :return: the name reformatted into the format expected for parameter-passing to an adb am isntrument command
        """
        items = name[1:-1].replace('/', '.').rsplit('.', 1)
        return "#".join(items)

    def find_junit3_tests(self, descriptors=list(junit3.Junit3Processor.DEFAULT_DESCRIPTORS)):
        test_classes = self.find_classes_directly_inherited_from(descriptors)
        method_names = []

        for class_def in test_classes:
            method_names += [m for m in self.find_method_names(class_def) if m.startswith("test")]

        return set(method_names)

    def find_junit4_tests(self):
        test_annotation_descriptor = "Lorg/junit/Test;"
        result = []
        for class_def in [c for c in self._ids[DexParser.ClassDefItem] if c.annotations_offset != 0]:

            directory = self._bytestream.parse_one_item(class_def.annotations_offset,
                                                        DexParser.AnnotationsDirectoryItem)
            names = directory.get_methods_with_annotation(test_annotation_descriptor,
                                                          self._ids[DexParser.MethodIdItem])
            result += [self._descriptor2name(class_def.descriptor) + "#" + name for name in names]

        return set(result)


def main():
    if len(sys.argv) != 2:
        print("Usage: dexdump <apk-file-name>")
        sys.exit(-1)
    tests = DexParser.parse(sys.argv[1])
    for test in tests:
        print(test)
