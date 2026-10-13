"""Build a dex of unused classes so a reverse engineer has extra paths to follow."""

from __future__ import annotations

import hashlib
import secrets
import string
import struct
import zipfile
from dataclasses import dataclass

_PUBLIC = 0x1
_STATIC = 0x8
_CONSTRUCTOR = 0x10000
_NO_INDEX = 0xFFFFFFFF

_HEADER_ITEM = 0x0000
_STRING_ID_ITEM = 0x0001
_TYPE_ID_ITEM = 0x0002
_PROTO_ID_ITEM = 0x0003
_METHOD_ID_ITEM = 0x0005
_CLASS_DEF_ITEM = 0x0006
_MAP_LIST = 0x1000
_TYPE_LIST = 0x1001
_CLASS_DATA_ITEM = 0x2000
_CODE_ITEM = 0x2001
_STRING_DATA_ITEM = 0x2002


@dataclass(frozen=True)
class _Proto:
    shorty: str
    return_type: str
    params: tuple[str, ...] = ()


@dataclass
class _Method:
    class_desc: str
    name: str
    proto: _Proto
    access: int
    insns: list[int | str]
    registers: int
    ins: int
    outs: int
    calls: _Method | None = None
    index: int = 0


def dex_type_descriptors(data: bytes) -> set[str]:
    """Return every type descriptor stored in a dex string pool."""
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        return set()
    count, start = struct.unpack_from("<II", data, 56)
    found: set[str] = set()
    for item in range(count):
        offset = struct.unpack_from("<I", data, start + item * 4)[0]
        _size, cursor = _read_uleb(data, offset)
        end = data.index(b"\x00", cursor)
        text = data[cursor:end].decode("utf-8", "replace")
        if text.startswith("L") and text.endswith(";"):
            found.add(text)
    return found


def next_dex_name(names: list[str]) -> str:
    """Pick the next ``classesN.dex`` entry at the archive root."""
    used = {1}
    for name in names:
        if "/" in name:
            continue
        if name == "classes.dex":
            used.add(1)
        elif (
            name.startswith("classes")
            and name.endswith(".dex")
            and name[7:-4].isdigit()
        ):
            used.add(int(name[7:-4]))
    number = 2
    while number in used:
        number += 1
    return f"classes{number}.dex"


def build_decoy_dex(
    class_count: int,
    *,
    seed: str | None = None,
    avoid: set[str] | None = None,
) -> tuple[bytes, tuple[str, ...], str]:
    """Return a dex, the dotted class names inside it, and the seed that built it.

    The same seed rebuilds the same classes. A missing seed is chosen at random
    so two runs do not share class names, strings, or bytecode.
    """
    if class_count < 1:
        raise ValueError("decoy class count must be at least 1")
    if class_count > 256:
        raise ValueError("decoy class count must be 256 or less")
    chosen = seed if seed else secrets.token_hex(8)
    rng = _Random(chosen)
    blocked = set(avoid or ())
    classes = [_plan_class(rng, blocked) for _item in range(class_count)]
    dex = _emit(classes)
    from softcloak.rewrite import fix_dex

    names = tuple(_dotted(item.descriptor) for item in classes)
    return fix_dex(dex), names, chosen


class _Random:
    """Small deterministic generator so a seed does not depend on hash randomization."""

    def __init__(self, seed: str) -> None:
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        self._state = int.from_bytes(digest, "big") or 1

    def randint(self, low: int, high: int) -> int:
        return low + self._number() % (high - low + 1)

    def chance(self, numerator: int, denominator: int) -> bool:
        return self._number() % denominator < numerator

    def choice(self, items: list[str]) -> str:
        return items[self._number() % len(items)]

    def _number(self) -> int:
        self._state = (self._state * 6364136223846793005 + 1) & ((1 << 64) - 1)
        return self._state >> 33


@dataclass
class _ClassPlan:
    descriptor: str
    methods: list[_Method]


def _plan_class(rng: _Random, blocked: set[str]) -> _ClassPlan:
    descriptor = _fresh_descriptor(rng, blocked)
    blocked.add(descriptor)
    methods = [_constructor(descriptor)]
    used_names = {"<init>"}

    def take_name() -> str:
        for _attempt in range(40):
            name = _method_name(rng)
            if name not in used_names:
                used_names.add(name)
                return name
        raise RuntimeError("could not choose a decoy method name")

    void_methods = [
        _void_method(descriptor, take_name(), rng) for _item in range(rng.randint(1, 3))
    ]
    methods.extend(void_methods)
    if len(void_methods) > 1 and rng.chance(1, 2):
        void_methods[-1].calls = void_methods[0]
    methods.append(_int_method(descriptor, take_name(), rng))
    if rng.chance(2, 3):
        methods.append(_string_method(descriptor, take_name(), rng))
    return _ClassPlan(descriptor, methods)


def _fresh_descriptor(rng: _Random, blocked: set[str]) -> str:
    for _attempt in range(50):
        segments = [
            _word(rng, 4, 10, upper=False) for _item in range(rng.randint(1, 3))
        ]
        simple = _word(rng, 6, 14, upper=True)
        descriptor = "L" + "/".join([*segments, simple]) + ";"
        if descriptor not in blocked and not descriptor.startswith(
            ("Ljava/", "Landroid/", "Lkotlin/", "Landroidx/", "Lcom/google/")
        ):
            return descriptor
    raise RuntimeError("could not choose a decoy class name")


def _word(rng: _Random, low: int, high: int, *, upper: bool) -> str:
    letters = string.ascii_lowercase
    count = rng.randint(low, high)
    first_source = string.ascii_uppercase if upper else letters
    return rng.choice(list(first_source)) + "".join(
        rng.choice(list(letters)) for _item in range(count - 1)
    )


def _method_name(rng: _Random) -> str:
    return _word(rng, 4, 12, upper=False)


def _constructor(descriptor: str) -> _Method:
    return _Method(
        descriptor,
        "<init>",
        _Proto("V", "V"),
        _PUBLIC | _CONSTRUCTOR,
        [],
        registers=1,
        ins=1,
        outs=1,
    )


def _void_method(descriptor: str, name: str, rng: _Random) -> _Method:
    insns = [0x0000] * rng.randint(0, 2) + [0x000E]
    return _Method(
        descriptor, name, _Proto("V", "V"), _PUBLIC | _STATIC, insns, 1, 0, 0
    )


def _int_method(descriptor: str, name: str, rng: _Random) -> _Method:
    live = rng.randint(1, 30000)
    dead = rng.randint(1, 30000)
    if rng.chance(1, 2):
        # v0 = 0; the branch is not taken. Both returns are ints, so the verifier accepts it.
        insns = [
            0x0012,
            0x0039,
            5,
            *_const16(0, live),
            0x000F,
            *_const16(0, dead),
            0x000F,
        ]
    else:
        insns = [*_const16(0, live), 0x000F]
    return _Method(
        descriptor, name, _Proto("I", "I"), _PUBLIC | _STATIC, insns, 1, 0, 0
    )


def _string_method(descriptor: str, name: str, rng: _Random) -> _Method:
    literal = _literal(rng)
    insns = [0x001A, literal, 0x0011]
    return _Method(
        descriptor,
        name,
        _Proto("L", "Ljava/lang/String;"),
        _PUBLIC | _STATIC,
        insns,
        1,
        0,
        0,
    )


def _literal(rng: _Random) -> str:
    kind = rng.randint(0, 2)
    if kind == 0:
        alphabet = "0123456789abcdef"
        count = 32 if rng.chance(1, 2) else 64
        return "".join(rng.choice(list(alphabet)) for _item in range(count))
    if kind == 1:
        alphabet = string.ascii_letters + string.digits + "+/"
        return "".join(
            rng.choice(list(alphabet)) for _item in range(rng.randint(16, 40))
        )
    left = _word(rng, 3, 8, upper=False)
    right = _word(rng, 3, 8, upper=False)
    tail = "".join(
        rng.choice(list(string.digits)) for _item in range(rng.randint(1, 3))
    )
    return f"{left}.{right}/{tail}"


def _const16(register: int, value: int) -> list[int]:
    return [0x0013 | (register << 8), value & 0xFFFF]


def _dotted(descriptor: str) -> str:
    return descriptor[1:-1].replace("/", ".")


def _emit(classes: list[_ClassPlan]) -> bytes:
    strings: set[str] = {
        "<init>",
        "V",
        "I",
        "L",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
    }
    for item in classes:
        strings.add(item.descriptor)
        for method in item.methods:
            strings.add(method.name)
            strings.add(method.proto.shorty)
            strings.add(method.proto.return_type)
            for word in method.insns:
                if isinstance(word, str):
                    strings.add(word)
    ordered_strings = sorted(strings)
    string_index = {text: index for index, text in enumerate(ordered_strings)}

    descriptors = sorted(
        {item.descriptor for item in classes}
        | {"Ljava/lang/Object;", "Ljava/lang/String;", "V", "I"}
    )
    type_index = {text: index for index, text in enumerate(descriptors)}

    protos: list[_Proto] = []
    seen_protos: set[tuple[str, str, tuple[str, ...]]] = set()
    for item in classes:
        for method in item.methods:
            key = (method.proto.shorty, method.proto.return_type, method.proto.params)
            if key not in seen_protos:
                seen_protos.add(key)
                protos.append(method.proto)
    protos.sort(key=lambda item: (type_index[item.return_type], item.params))
    proto_index = {
        (item.shorty, item.return_type, item.params): index
        for index, item in enumerate(protos)
    }

    methods = [method for item in classes for method in item.methods]
    object_init = _Method(
        "Ljava/lang/Object;",
        "<init>",
        _Proto("V", "V"),
        _PUBLIC | _CONSTRUCTOR,
        [],
        0,
        0,
        0,
    )
    all_methods = [*methods, object_init]
    all_methods.sort(
        key=lambda item: (
            type_index[item.class_desc],
            string_index[item.name],
            proto_index[(item.proto.shorty, item.proto.return_type, item.proto.params)],
        )
    )
    for index, method in enumerate(all_methods):
        method.index = index

    for method in methods:
        if method.name == "<init>":
            method.insns = _invoke_direct(object_init) + [0x000E]
        elif method.calls is not None:
            method.insns = [0x0071, method.calls.index, 0x0000, 0x000E]
        else:
            method.insns = [_resolve_word(word, string_index) for word in method.insns]

    return _layout(
        ordered_strings,
        descriptors,
        protos,
        all_methods,
        classes,
        string_index,
        type_index,
        proto_index,
    )


def _invoke_direct(target: _Method) -> list[int]:
    return [0x1070, target.index, 0x0000]


def _resolve_word(word: int | str, string_index: dict[str, int]) -> int:
    if isinstance(word, str):
        return string_index[word]
    return word


def _layout(
    strings: list[str],
    descriptors: list[str],
    protos: list[_Proto],
    methods: list[_Method],
    classes: list[_ClassPlan],
    string_index: dict[str, int],
    type_index: dict[str, int],
    proto_index: dict[tuple[str, str, tuple[str, ...]], int],
) -> bytes:
    string_ids_off = 0x70
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + len(descriptors) * 4
    method_ids_off = proto_ids_off + len(protos) * 12
    class_defs_off = method_ids_off + len(methods) * 8
    data_off = class_defs_off + len(classes) * 32

    string_blob = bytearray()
    string_offsets: list[int] = []
    for text in strings:
        string_offsets.append(data_off + len(string_blob))
        encoded = text.encode("utf-8")
        string_blob += _uleb(len(text)) + encoded + b"\x00"

    type_lists = bytearray()
    # No generated method takes parameters, so the parameter lists stay empty.

    code_blob = bytearray()
    code_offsets: dict[int, int] = {}
    code_base = _align_size(data_off + len(string_blob) + len(type_lists))
    padding = code_base - (data_off + len(string_blob))
    for method in methods:
        if method.class_desc == "Ljava/lang/Object;":
            continue
        code_offsets[method.index] = code_base + len(code_blob)
        code_blob += _code_item(method)
        while len(code_blob) % 4:
            code_blob.append(0)

    class_data_blob = bytearray()
    class_data_offsets: list[int] = []
    class_data_base = code_base + len(code_blob)
    for item in sorted(classes, key=lambda entry: type_index[entry.descriptor]):
        class_data_offsets.append(class_data_base + len(class_data_blob))
        class_data_blob += _class_data(item, code_offsets)

    map_off = _align_size(class_data_base + len(class_data_blob))
    data_pad = b"\x00" * padding
    tail_pad = b"\x00" * (map_off - (class_data_base + len(class_data_blob)))

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 36, 0x70)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<II", header, 56, len(strings), string_ids_off)
    struct.pack_into("<II", header, 64, len(descriptors), type_ids_off)
    struct.pack_into("<II", header, 72, len(protos), proto_ids_off)
    struct.pack_into("<II", header, 88, len(methods), method_ids_off)
    struct.pack_into("<II", header, 96, len(classes), class_defs_off)

    parts = [
        bytes(header),
        b"".join(struct.pack("<I", offset) for offset in string_offsets),
        b"".join(struct.pack("<I", string_index[text]) for text in descriptors),
        b"".join(_proto_item(item, string_index, type_index) for item in protos),
        b"".join(
            _method_item(item, string_index, type_index, proto_index)
            for item in methods
        ),
        b"".join(
            _class_def(item, type_index, class_data_offsets[index])
            for index, item in enumerate(
                sorted(classes, key=lambda entry: type_index[entry.descriptor])
            )
        ),
        bytes(string_blob),
        data_pad,
        bytes(type_lists),
        bytes(code_blob),
        bytes(class_data_blob),
        tail_pad,
    ]
    body = b"".join(parts)
    map_list = _map_list(
        [
            (_HEADER_ITEM, 1, 0),
            (_STRING_ID_ITEM, len(strings), string_ids_off),
            (_TYPE_ID_ITEM, len(descriptors), type_ids_off),
            (_PROTO_ID_ITEM, len(protos), proto_ids_off),
            (_METHOD_ID_ITEM, len(methods), method_ids_off),
            (_CLASS_DEF_ITEM, len(classes), class_defs_off),
            (_STRING_DATA_ITEM, len(strings), data_off),
            (_CODE_ITEM, len(code_offsets), code_base),
            (_CLASS_DATA_ITEM, len(classes), class_data_base),
            (_MAP_LIST, 1, map_off),
        ]
    )
    file_bytes = body + map_list
    if len(file_bytes) != map_off + len(map_list):
        raise RuntimeError("decoy dex layout does not match the map")
    header = bytearray(file_bytes)
    struct.pack_into("<I", header, 32, len(header))
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<II", header, 104, len(header) - data_off, data_off)
    return bytes(header)


def _proto_item(
    proto: _Proto, string_index: dict[str, int], type_index: dict[str, int]
) -> bytes:
    return struct.pack(
        "<III",
        string_index[proto.shorty],
        type_index[proto.return_type],
        0,
    )


def _method_item(
    method: _Method,
    string_index: dict[str, int],
    type_index: dict[str, int],
    proto_index: dict[tuple[str, str, tuple[str, ...]], int],
) -> bytes:
    return struct.pack(
        "<HHI",
        type_index[method.class_desc],
        proto_index[
            (method.proto.shorty, method.proto.return_type, method.proto.params)
        ],
        string_index[method.name],
    )


def _class_def(item: _ClassPlan, type_index: dict[str, int], data_off: int) -> bytes:
    return struct.pack(
        "<IIIIIIII",
        type_index[item.descriptor],
        _PUBLIC,
        type_index["Ljava/lang/Object;"],
        0,
        _NO_INDEX,
        0,
        data_off,
        0,
    )


def _class_data(item: _ClassPlan, code_offsets: dict[int, int]) -> bytes:
    ordered = sorted(item.methods, key=lambda method: method.index)
    blob = bytearray(_uleb(0) + _uleb(0) + _uleb(len(ordered)) + _uleb(0))
    previous = 0
    for method in ordered:
        blob += _uleb(method.index - previous)
        blob += _uleb(method.access)
        blob += _uleb(code_offsets[method.index])
        previous = method.index
    return bytes(blob)


def _code_item(method: _Method) -> bytes:
    insns = b"".join(struct.pack("<H", word & 0xFFFF) for word in method.insns)
    return (
        struct.pack(
            "<HHHHII",
            method.registers,
            method.ins,
            method.outs,
            0,
            0,
            len(method.insns),
        )
        + insns
    )


def _map_list(items: list[tuple[int, int, int]]) -> bytes:
    ordered = sorted(items, key=lambda item: item[2])
    blob = struct.pack("<I", len(ordered))
    for item_type, size, offset in ordered:
        blob += struct.pack("<HHII", item_type, 0, size, offset)
    return blob


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        piece = value & 0x7F
        value >>= 7
        if value:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def _read_uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def _align_size(value: int) -> int:
    return (value + 3) & ~3


def decoy_zip_entry(
    names: list[str],
    class_count: int,
    *,
    seed: str | None,
    avoid: set[str],
    date_time: tuple[int, int, int, int, int, int],
) -> tuple[zipfile.ZipInfo, bytes, tuple[str, ...], str]:
    """Build the zip entry that holds the decoy dex."""
    payload, class_names, used_seed = build_decoy_dex(
        class_count, seed=seed, avoid=avoid
    )
    info = zipfile.ZipInfo(next_dex_name(names), date_time=date_time)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info, payload, class_names, used_seed
