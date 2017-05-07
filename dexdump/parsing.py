import os
import shutil
import sys
import tempfile
import zipfile
from abc import ABCMeta
from functools import lru_cache

from dexdump import junit3
from . import ByteStream


class DexFormatException(Exception):
    """
    General exception thrown on dex format inconsistency
    """
    def __init__(self, msg):
        super(DexFormatException, self).__init__(msg)


class DexParser(object):

    class DexMagic(object):
        """
        Magic numbers for validation of dex file
        """
        SIZE_MAGIC_DEX = 3
        SIZE_MAGIC_VERSION = 3

        EXPECTED_DEX = bytes([0x64, 0x65, 0x78])
        EXPECTED_VERSION = bytes([0x30, 0x33, 0x35])

        def __init__(self, bytestream):
            self._dex = bytestream.read_bytes(DexParser.DexMagic.SIZE_MAGIC_DEX)
            self._newline = bytestream.read_byte()
            self._version = bytestream.read_bytes(DexParser.DexMagic.SIZE_MAGIC_VERSION)
            self._zero = bytestream.read_byte()

        def validate(self):
            return (self._dex == DexParser.DexMagic.EXPECTED_DEX and self._newline == 0x0A and
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
            self._file_size = bytestream.read_int()
            self._header_size = bytestream.read_int()
            self._endian_tag = bytestream.read_int()
            self._link_size = bytestream.read_int()
            self._link_offset = bytestream.read_int()
            self._map_offset = bytestream.read_int()
            self._size_and_offset = {}
            for clazz in [DexParser.StringIdItem, DexParser.TypeIdItem, DexParser.ProtoIdItem,
                          DexParser.FieldIdItem, DexParser.MethodIdItem, DexParser.ClassDefItem, DexParser.ClassDefData]:
                # define for each data class the size and offset of where that class's data is stored
                self._size_and_offset[clazz] = (bytestream.read_int(), bytestream.read_int())

        def size_and_offset(self, clazz):
            return self._size_and_offset.get(clazz)

        def validate(self):
            """
            :raises: `DexFormatException` if data read from dex file fails validation checks
            """
            if not self._magic.validate():
                raise DexFormatException("Invalid dex magic in dex file")
            if self._endian_tag != DexParser.Header.EXPECTED_ENDIAN_TAG:
                raise DexFormatException("Invalid endian-ness/tag in dex file")

    ###############################
    # Various data classes for holding dex-item data
    # These basically pull byte data out of the dex file to be interpreted into various classes of data
    ###############################

    class Item(metaclass=ABCMeta):
        """
        base class for all data items
        """

        def __init__(self, bytestrean):
            self._type_ids = None
            self._string_ids = None
            self._bytestream = bytestrean

        def set_type_string_ids(self, type_ids, string_ids):
            """
            Set type and string id arrays, are these are more ubiguitous in use in getting desciptors
            """
            self._type_ids = type_ids
            self._string_ids = string_ids

    class Annotation(Item):

        def __init__(self, bytestream):
            super(DexParser.Annotation, self).__init__(bytestream)
            self._index = bytestream.read_int()
            self._annotations_offset = bytestream.read_int()

    class AnnotationItem(Item):

        def __init__(self, bytestream):
            super(DexParser.AnnotationItem, self).__init__(bytestream)
            self._visibility = bytestream.read_byte()
            self._encoded_annotation = bytestream.parse_items(1, None, DexParser.EncodedAnnotation)[0]

    class AnnotationOffsetItem(Item):

        def __init__(self, bytestream):
            super(DexParser.AnnotationOffsetItem, self).__init__(bytestream)
            self._annotation_offset = bytestream.read_int()

    class AnnotationSetItem(Item):

        def __init__(self, bytestream):
            super(DexParser.AnnotationSetItem, self).__init__(bytestream)
            self._entries = self._bytestream.parse_items(None, None, DexParser.AnnotationOffsetItem)

        def __iter__(self):
            for item in self._entries:
                yield item

    class AnnotationElement(Item):

        def __init__(self, bytestream):
            super(DexParser.AnnotationElement, self).__init__(bytestream)
            self._name_index = bytestream.read_leb128()
            self._value = bytestream.parse_items(1, None, DexParser.EncodedValue)[0]

    class AnnotationsDirectoryItem(Item):

        def __init__(self, bytestream):
            super(DexParser.AnnotationsDirectoryItem, self).__init__(bytestream)
            self._class_annotations_offset = bytestream.read_int()
            self._field_size = bytestream.read_int()
            self._annotated_method_size = bytestream.read_int()
            self._annotated_parameter_size = bytestream.read_int()
            self._field_annotations = bytestream.parse_items(self._field_size, None, DexParser.Annotation)
            self._method_annotations = bytestream.parse_items(self._annotated_method_size, None, DexParser.Annotation)
            self._parameter_annotations = bytestream.parse_items(self._annotated_parameter_size, None, DexParser.Annotation)

        def get_methods_with_annotation(self, descriptor, method_ids):
            """
            :return: all vritual methods int his directory of that ar annotated with given descriptor
            """
            results = []
            for annotation in self._method_annotations:
                for entries in self._bytestream.parse_items(1, annotation._annotations_offset, DexParser.AnnotationSetItem):
                    for entry in entries:
                        item = self._bytestream.parse_items(1, entry._annotation_offset, DexParser.AnnotationItem)[0]
                        type_id = self._type_ids[item._encoded_annotation._type_index]
                        string_id = self._string_ids[type_id._descriptor_index]
                        if descriptor == self._bytestream.parse_descriptor(type_id, string_id):
                            method_id = method_ids[annotation._method_index]
                            descriptor = self._bytestream.parse_method_name(method_id)
                            results.append(DexParser._reformat(descriptor))
                            break
            return set(results)

    class ClassDefItem(Item):

        def __init__(self, bytestream):
            super(DexParser.ClassDefItem, self).__init__(bytestream)
            self._class_index = bytestream.read_int()
            self._access_flags = bytestream.read_int()
            self._super_class_index = bytestream.read_int()
            self._interfaces_offset = bytestream.read_int()
            self._source_file_index = bytestream.read_int()
            self._annotations_offset = bytestream.read_int()
            self._class_data_offset = bytestream.read_int()
            self._static_values_offset = bytestream.read_int()
            self._super_type = None

        @lru_cache(maxsize=None)
        def super_descriptor(self):
            """
            :return: the string descriptor (cached) of the super class of this class def
            """
            desc_index = self.super_type()._descriptor_index
            string_id = self._string_ids[desc_index]
            return self._bytestream.parse_descriptor(self._super_type, string_id)

        @lru_cache(maxsize=None)
        def super_type(self):
            """
            :return: type TypeIdItem of the super class or None if no inheritance
            """
            if self._super_class_index < 0:
                return None
            return self._type_ids[self._super_class_index]

        def has_direct_super_class(self, descriptors):
            """
            :return: whether this class inherits from one of the classes defined by the given descriptors
            """
            if self._super_class_index < 0:
                return False
            return self.super_descriptor() in descriptors

    class ClassDefData(Item):
        def __init__(self, bytestream):
            super(DexParser.ClassDefData, self).__init__(bytestream)
            self._static_fields_size = bytestream.read_leb128()
            self._instance_fields_size = bytestream.read_leb128()
            self._direct_methods_size = bytestream.read_leb128()
            self._virtual_methods_size = bytestream.read_leb128()
            self._static_fields = bytestream.parse_items(self._static_fields_size, None, DexParser.EncodedField)
            self._instance_fields = bytestream.parse_items(self._instance_fields_size, None, DexParser.EncodedField)
            self._direct_methods = bytestream.parse_items(self._direct_methods_size, None, DexParser.EncodedMethod)
            self._virtual_methods = bytestream.parse_items(self._virtual_methods_size, None, DexParser.EncodedMethod)

    class EncodedAnnotation(Item):
        def __init__(self, bytestream):
            super(DexParser.EncodedAnnotation, self).__init__(bytestream)
            self._type_index = bytestream.read_leb128()
            self._size = bytestream.read_leb128()
            self._elements = bytestream.parse_items(self._size, None, DexParser.AnnotationElement)

    class EncodedItem(Item):

        def __init__(self, bytestream):
            super(DexParser.EncodedItem, self).__init__(bytestream)
            self._index_diff = bytestream.read_leb128()
            self._access_flags = bytestream.read_leb128()


    EncodedField = EncodedItem

    class EncodedMethod(EncodedItem):

        def __init__(self, bytestream):
            super(DexParser.EncodedMethod, self).__init__(bytestream)
            self._code_offset = bytestream.read_leb128()

        @lru_cache(maxsize=None)
        def method_name(self, method_ids):
            method_id = method_ids[self._index_diff]
            return self._bytestream.parse_method_name(self, method_id)

    class EncodedArray(Item):

        def __init__(self, bytestream):
            super(DexParser.EncodedArray, self).__init__(bytestream)
            self._size = bytestream.read_leb128()
            self._value = bytestream.parse_items(self._size, None, DexParser.EncodedValue)

    class EncodedValue(Item):

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
                self._value = bytestream.parse_items(None, None, DexParser.EncodedArray)
            elif value_type == DexParser.EncodedValue.VALUE_ANNOTATION:
                self._value = bytestream.parse_items(1, None, DexParser.EncodedAnnotation)
            elif value_type == DexParser.EncodedValue.VALUE_NULL:
                self._value = bytes([])
            elif value_type == DexParser.EncodedValue.VALUE_BOOLEAN:
                self._value = bytestream.read_bytes(value_arg)

    class FieldIdItem(Item):

        def __init__(self, bytestream):
            super(DexParser.FieldIdItem, self).__init__(bytestream)
            self._class_index = bytestream.read_short()
            self._type_index = bytestream.read_short()
            self._name_index = bytestream.read_int()

    class MethodIdItem(Item):

        def __init__(self, bytestream):
            super(DexParser.MethodIdItem, self).__init__(bytestream)
            self._class_index = bytestream.read_short()
            self._proto_index = bytestream.read_short()
            self._name_index = bytestream.read_int()

    class ProtoIdItem(Item):

        def __init__(self, bytestream):
            super(DexParser.ProtoIdItem, self).__init__(bytestream)
            self._shorty_index = bytestream.read_int()
            self._return_type_index = bytestream.read_int()
            self._parameters_offset = bytestream.read_int()

    class StringIdItem(Item):

        def __init__(self, bytestream):
            super(DexParser.StringIdItem, self).__init__(bytestream)
            self._data_offset = bytestream.read_int()

    class TypeIdItem(Item):

        def __init__(self, bytestream):
            super(DexParser.TypeIdItem, self).__init__(bytestream)
            self._descriptor_index = bytestream.read_int()

    #
    #####################


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

    def __init__(self, file_name):
        self._bytestream = ByteStream(file_name)
        self._headers = DexParser.Header(self._bytestream)
        self._headers.validate()
        self._ids = {}
        for clazz in [DexParser.StringIdItem, DexParser.TypeIdItem, DexParser.ProtoIdItem,
                      DexParser.FieldIdItem, DexParser.MethodIdItem, DexParser.ClassDefItem]:
            size, offset = self._headers.size_and_offset(clazz)
            self._ids[clazz] = self._bytestream.parse_items(size, offset, clazz)
            if DexParser.TypeIdItem in self._ids:
                for item in self._ids[clazz]:
                    item.set_type_string_ids(self._ids[DexParser.TypeIdItem], self._ids[DexParser.StringIdItem])

    def find_classes_directly_inherited_from(self, descriptors):
        """
        :return: all classes that are directly inherited form one of the classes described by the descriptors
        """
        matching_classes = []
        type_id = self._ids[DexParser.TypeIdItem]
        for clazz in [c for c in self._ids[DexParser.ClassDefItem] if c.has_direct_super_class(descriptors)]:
            matching_classes.append(clazz)
            string_id = self._ids[DexParser.StringIdItem][type_id._descriptor_index]
            descriptors.append(self._bytestream.parse_descriptor(type_id, string_id))
        return matching_classes

    def find_method_names(self, class_def):
        """
        :return: all method names for a given class def
        """
        class_data = self._bytestream.parse_items(1, class_def._class_data_offset, DexParser.ClassDefData)[0]
        return [m.method_name(self._ids[DexParser.MethodIdItem]) for m in class_data._virtual_methods]

    @staticmethod
    def _reformat(name):
        """
        :return: the name reformatted into the format expected for parameter-passing to an adb am isntrument command
        """
        items = name.rsplit('.', 1)
        return "#".join(items)

    def find_junit3_tests(self, descriptors=set(junit3.Junit3Processor.DEFAULT_DESCRIPTORS)):
        test_classes = self.find_classes_directly_inherited_from(descriptors)
        method_names = []

        for class_def in test_classes:
            method_names += [self._reformat(m) for m in self.find_method_names(class_def) if m.startswith("test")]

        return set(method_names)

    def find_junit4_tests(self):
        test_annotation_descriptor = "L/org/junit/Test;"
        result = []
        for directory in [self._bytestream.parse_items(1, cdef._annotations_offset, DexParser.AnnotationsDirectoryItem)[0] for
                          cdef in self._ids[DexParser.ClassDefItem] if cdef._annotations_offset != 0]:
            directory.set_type_string_ids(self._ids[DexParser.TypeIdItem], self._ids[DexParser.StringIdItem])
            result += [self._reformat(name) for name in directory.get_methods_with_annotation(test_annotation_descriptor, self._ids[DexParser.MethodIdItem])]
        return set(result)


def main():
    if len(sys.argv) != 2:
        print("Usage: dexdump <apk-file-name>")
        sys.exit(-1)
    tests = DexParser.parse(sys.argv[1])
    print ("FOUND:\n%s" % tests)