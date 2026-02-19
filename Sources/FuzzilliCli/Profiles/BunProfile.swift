// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Fuzzilli

// MARK: - Bun Type Definitions

public extension ILType {
    // Buffer encoding enum values
    static let bufferEncodingEnum = ILType.enumeration(ofName: "BufferEncoding", withValues: [
        "utf8", "utf-8", "utf16le", "ucs2", "ucs-2", "base64", "base64url", "latin1", "binary", "hex", "ascii"
    ])

    // Hash algorithm enum values
    static let hashAlgorithmEnum = ILType.enumeration(ofName: "HashAlgorithm", withValues: [
        "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512-256",
        "blake2b256", "blake2b512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"
    ])

    // Digest format enum values
    static let digestFormatEnum = ILType.enumeration(ofName: "DigestFormat", withValues: [
        "hex", "base64", "buffer"
    ])

    // CSS color format enum values
    static let colorFormatEnum = ILType.enumeration(ofName: "ColorFormat", withValues: [
        "css", "ansi", "ansi-16", "ansi-256", "ansi-16m", "rgb", "rgba",
        "hsl", "hex", "HEX", "{rgb}", "{rgba}", "[rgb]", "[rgba]"
    ])

    // BunCryptoHasher - Incremental hashing utility
    static let bunCryptoHasher = ILType.object(
        ofGroup: "CryptoHasher",
        withProperties: [],
        withMethods: ["update", "digest", "copy"]
    )

    // BunTranspiler - Code transpilation/parsing
    static let bunTranspiler = ILType.object(
        ofGroup: "Transpiler",
        withProperties: [],
        withMethods: ["transformSync", "scan", "scanImports"]
    )

    // BunPasswordHasher - Password hashing namespace
    static let bunPasswordHasher = ILType.object(
        ofGroup: "PasswordHasher",
        withProperties: [],
        withMethods: ["hashSync", "verifySync"]
    )

    // BunGlob - Pattern matching
    static let bunGlob = ILType.object(
        ofGroup: "Glob",
        withProperties: [],
        withMethods: ["match", "scan", "scanSync"]
    )

    // HTMLRewriter Element - HTML element manipulation
    static let htmlRewriterElement = ILType.object(
        ofGroup: "HTMLRewriterElement",
        withProperties: ["tagName", "namespaceURI", "attributes", "removed", "selfClosing", "canHaveContent"],
        withMethods: ["getAttribute", "setAttribute", "hasAttribute", "removeAttribute", "setInnerContent", "append", "prepend", "before", "after", "remove", "removeAndKeepContent", "onEndTag"]
    )

    // HTMLRewriter Text - Text node manipulation
    static let htmlRewriterText = ILType.object(
        ofGroup: "HTMLRewriterText",
        withProperties: ["text", "removed"],
        withMethods: ["before", "after", "replace", "remove"]
    )

    // HTMLRewriter Comment - Comment node manipulation
    static let htmlRewriterComment = ILType.object(
        ofGroup: "HTMLRewriterComment",
        withProperties: ["text", "removed"],
        withMethods: ["before", "after", "replace", "remove"]
    )

    // HTMLRewriter - HTML transformation with CSS selectors
    static let htmlRewriter = ILType.object(
        ofGroup: "HTMLRewriter",
        withProperties: [],
        withMethods: ["on", "onDocument", "transform"]
    )

    // BunTOML - TOML parser
    static let bunTOML = ILType.object(
        ofGroup: "BunTOML",
        withProperties: [],
        withMethods: ["parse"]
    )

    // BunYAML - YAML parser/stringifier
    static let bunYAML = ILType.object(
        ofGroup: "BunYAML",
        withProperties: [],
        withMethods: ["parse", "stringify"]
    )

    // BunHashConstructor - Hash algorithm constructors (Bun.MD4, Bun.SHA256, etc.)
    // These are constructor objects that also have a static .hash method
    static let bunHashConstructor = ILType.object(
        ofGroup: "BunHashConstructor",
        withProperties: [],
        withMethods: ["hash"]
    )
}

// MARK: - Bun ObjectGroup Definitions

public let bunCryptoHasherGroup = ObjectGroup(
    name: "CryptoHasher",
    instanceType: .bunCryptoHasher,
    properties: [:],
    methods: [
        "update": [.jsAnything, .opt(.string)] => .bunCryptoHasher,
        "digest": [.opt(.string)] => (.object() | .string),
        "copy":   [] => .bunCryptoHasher,
    ]
)

public let bunTranspilerGroup = ObjectGroup(
    name: "Transpiler",
    instanceType: .bunTranspiler,
    properties: [:],
    methods: [
        "transformSync": [.string, .opt(.string)] => .string,
        "scan":          [.string] => .object(),
        "scanImports":   [.string] => .jsArray,
    ]
)

public let bunPasswordHasherGroup = ObjectGroup(
    name: "PasswordHasher",
    instanceType: .bunPasswordHasher,
    properties: [:],
    methods: [
        "hashSync":   [.string, .opt(.object())] => .string,
        "verifySync": [.string, .string] => .boolean,
    ]
)

public let bunGlobGroup = ObjectGroup(
    name: "Glob",
    instanceType: .bunGlob,
    properties: [:],
    methods: [
        "match":    [.string] => .object(),  // Returns iterator of matches
        "scan":     [.opt(.string)] => .object(),  // Returns iterator
        "scanSync": [.opt(.string)] => .jsArray,   // Returns array synchronously
    ]
)

public let htmlRewriterElementGroup = ObjectGroup(
    name: "HTMLRewriterElement",
    instanceType: .htmlRewriterElement,
    properties: [
        "tagName":       .string,
        "namespaceURI":  .string,
        "attributes":    .object(),
        "removed":       .boolean,
        "selfClosing":   .boolean,
        "canHaveContent": .boolean,
    ],
    methods: [
        "getAttribute":         [.string] => .jsAnything,
        "setAttribute":         [.string, .string] => .htmlRewriterElement,
        "hasAttribute":         [.string] => .boolean,
        "removeAttribute":      [.string] => .htmlRewriterElement,
        "setInnerContent":      [.string] => .htmlRewriterElement,
        "append":               [.string, .opt(.object())] => .htmlRewriterElement,
        "prepend":              [.string, .opt(.object())] => .htmlRewriterElement,
        "before":               [.string, .opt(.object())] => .htmlRewriterElement,
        "after":                [.string, .opt(.object())] => .htmlRewriterElement,
        "remove":               [] => .htmlRewriterElement,
        "removeAndKeepContent": [] => .htmlRewriterElement,
        "onEndTag":             [.function()] => .undefined,
    ]
)

public let htmlRewriterTextGroup = ObjectGroup(
    name: "HTMLRewriterText",
    instanceType: .htmlRewriterText,
    properties: [
        "text":    .string,
        "removed": .boolean,
    ],
    methods: [
        "before":  [.string, .opt(.object())] => .htmlRewriterText,
        "after":   [.string, .opt(.object())] => .htmlRewriterText,
        "replace": [.string, .opt(.object())] => .htmlRewriterText,
        "remove":  [] => .htmlRewriterText,
    ]
)

public let htmlRewriterCommentGroup = ObjectGroup(
    name: "HTMLRewriterComment",
    instanceType: .htmlRewriterComment,
    properties: [
        "text":    .string,
        "removed": .boolean,
    ],
    methods: [
        "before":  [.string, .opt(.object())] => .htmlRewriterComment,
        "after":   [.string, .opt(.object())] => .htmlRewriterComment,
        "replace": [.string, .opt(.object())] => .htmlRewriterComment,
        "remove":  [] => .htmlRewriterComment,
    ]
)

public let htmlRewriterGroup = ObjectGroup(
    name: "HTMLRewriter",
    instanceType: .htmlRewriter,
    properties: [:],
    methods: [
        "on":         [.string, .object()] => .htmlRewriter,
        "onDocument": [.object()] => .htmlRewriter,
        "transform":  [.plain(.bunResponse)] => .bunResponse,
    ]
)

public let bunTOMLGroup = ObjectGroup(
    name: "BunTOML",
    instanceType: .bunTOML,
    properties: [:],
    methods: [
        "parse": [.string] => .jsAnything,
    ]
)

public let bunYAMLGroup = ObjectGroup(
    name: "BunYAML",
    instanceType: .bunYAML,
    properties: [:],
    methods: [
        "parse":     [.string] => .jsAnything,
        "stringify": [.jsAnything, .opt(.jsAnything), .opt(.jsAnything)] => .string,
    ]
)

// ObjectGroup for hash constructors (Bun.MD4, Bun.SHA256, etc.)
// These are constructor functions that also have a static .hash method
public let bunHashConstructorGroup = ObjectGroup(
    name: "BunHashConstructor",
    instanceType: .bunHashConstructor,
    properties: [:],
    methods: [
        "hash": [.jsAnything, .opt(.string)] => .jsAnything,
    ]
)

// Options object for hash operations
public let bunHashOptions = ObjectGroup(
    name: "BunHashOptions",
    instanceType: .object(ofGroup: "BunHashOptions", withProperties: ["algorithm", "encoding"], withMethods: []),
    properties: [
        "algorithm": .hashAlgorithmEnum,
        "encoding": .bufferEncodingEnum,
    ],
    methods: [:]
)

// Options object for color parsing
public let bunColorOptions = ObjectGroup(
    name: "BunColorOptions",
    instanceType: .object(ofGroup: "BunColorOptions", withProperties: ["format"], withMethods: []),
    properties: [
        "format": .colorFormatEnum,
    ],
    methods: [:]
)

// MARK: - Bun Web API Types

public extension ILType {
    // Buffer type
    static let bunBuffer = ILType.object(
        ofGroup: "Buffer",
        withProperties: ["length", "byteLength", "byteOffset", "buffer"],
        withMethods: ["toString", "toJSON", "equals", "compare", "copy", "slice", "subarray",
                      "write", "writeBigInt64BE", "writeBigInt64LE", "writeBigUInt64BE", "writeBigUInt64LE",
                      "writeDoubleBE", "writeDoubleLE", "writeFloatBE", "writeFloatLE",
                      "writeInt8", "writeInt16BE", "writeInt16LE", "writeInt32BE", "writeInt32LE",
                      "writeUInt8", "writeUInt16BE", "writeUInt16LE", "writeUInt32BE", "writeUInt32LE",
                      "readBigInt64BE", "readBigInt64LE", "readBigUInt64BE", "readBigUInt64LE",
                      "readDoubleBE", "readDoubleLE", "readFloatBE", "readFloatLE",
                      "readInt8", "readInt16BE", "readInt16LE", "readInt32BE", "readInt32LE",
                      "readUInt8", "readUInt16BE", "readUInt16LE", "readUInt32BE", "readUInt32LE",
                      "swap16", "swap32", "swap64", "fill", "indexOf", "lastIndexOf", "includes"]
    )

    // TextEncoder type
    static let bunTextEncoder = ILType.object(
        ofGroup: "TextEncoder",
        withProperties: ["encoding"],
        withMethods: ["encode", "encodeInto"]
    )

    // TextDecoder type
    static let bunTextDecoder = ILType.object(
        ofGroup: "TextDecoder",
        withProperties: ["encoding", "fatal", "ignoreBOM"],
        withMethods: ["decode"]
    )

    // URL type
    static let bunURL = ILType.object(
        ofGroup: "URL",
        withProperties: ["href", "origin", "protocol", "username", "password", "host", "hostname",
                         "port", "pathname", "search", "searchParams", "hash"],
        withMethods: ["toString", "toJSON"]
    )

    // URLSearchParams type
    static let bunURLSearchParams = ILType.object(
        ofGroup: "URLSearchParams",
        withProperties: ["size"],
        withMethods: ["append", "delete", "get", "getAll", "has", "set", "sort", "toString",
                      "entries", "keys", "values", "forEach"]
    )

    // FormData type
    static let bunFormData = ILType.object(
        ofGroup: "FormData",
        withProperties: [],
        withMethods: ["append", "delete", "get", "getAll", "has", "set", "entries", "keys", "values", "forEach"]
    )

    // Blob type
    static let bunBlob = ILType.object(
        ofGroup: "Blob",
        withProperties: ["size", "type"],
        withMethods: ["slice", "stream", "text", "arrayBuffer"]
    )

    // Fetch/Request/Response types
    static let bunHeaders = ILType.object(
        ofGroup: "Headers",
        withProperties: [],
        withMethods: ["append", "delete", "get", "has", "set", "entries", "keys", "values", "forEach"]
    )

    static let bunRequest = ILType.object(
        ofGroup: "Request",
        withProperties: ["method", "url", "headers", "body", "bodyUsed", "cache", "credentials", "destination", "integrity", "mode", "redirect", "referrer", "referrerPolicy"],
        withMethods: ["clone", "arrayBuffer", "blob", "formData", "json", "text"]
    )

    static let bunResponse = ILType.object(
        ofGroup: "Response",
        withProperties: ["ok", "status", "statusText", "headers", "body", "bodyUsed", "type", "url", "redirected"],
        withMethods: ["clone", "arrayBuffer", "blob", "formData", "json", "text"]
    )
}

public let bunHeadersGroup = ObjectGroup(
    name: "Headers",
    instanceType: .bunHeaders,
    properties: [:],
    methods: [
        "append":  [.string, .string] => .undefined,
        "delete":  [.string] => .undefined,
        "get":     [.string] => (.string | .undefined),
        "has":     [.string] => .boolean,
        "set":     [.string, .string] => .undefined,
        "entries": [] => .object(),
        "keys":    [] => .object(),
        "values":  [] => .object(),
        "forEach": [.function()] => .undefined,
    ]
)

public let bunRequestGroup = ObjectGroup(
    name: "Request",
    instanceType: .bunRequest,
    properties: [
        "method":         .string,
        "url":            .string,
        "headers":        .bunHeaders,
        "body":           .object(),
        "bodyUsed":       .boolean,
        "cache":          .string,
        "credentials":    .string,
        "destination":    .string,
        "integrity":      .string,
        "mode":           .string,
        "redirect":       .string,
        "referrer":       .string,
        "referrerPolicy": .string,
    ],
    methods: [
        "clone":       [] => .bunRequest,
        "arrayBuffer": [] => .jsPromise,
        "blob":        [] => .jsPromise,
        "formData":    [] => .jsPromise,
        "json":        [] => .jsPromise,
        "text":        [] => .jsPromise,
    ]
)

public let bunResponseGroup = ObjectGroup(
    name: "Response",
    instanceType: .bunResponse,
    properties: [
        "ok":         .boolean,
        "status":     .integer,
        "statusText": .string,
        "headers":    .bunHeaders,
        "body":       .object(),
        "bodyUsed":   .boolean,
        "type":       .string,
        "url":        .string,
        "redirected": .boolean,
    ],
    methods: [
        "clone":       [] => .bunResponse,
        "arrayBuffer": [] => .jsPromise,
        "blob":        [] => .jsPromise,
        "formData":    [] => .jsPromise,
        "json":        [] => .jsPromise,
        "text":        [] => .jsPromise,
    ]
)

public let bunBufferGroup = ObjectGroup(
    name: "Buffer",
    instanceType: .bunBuffer,
    properties: [
        "length":     .integer,
        "byteLength": .integer,
        "byteOffset": .integer,
        "buffer":     .object(),
    ],
    methods: [
        "toString":         [.opt(.string), .opt(.integer), .opt(.integer)] => .string,
        "toJSON":           [] => .object(),
        "equals":           [.object()] => .boolean,
        "compare":          [.object(), .opt(.integer), .opt(.integer), .opt(.integer), .opt(.integer)] => .integer,
        "copy":             [.object(), .opt(.integer), .opt(.integer), .opt(.integer)] => .integer,
        "slice":            [.opt(.integer), .opt(.integer)] => .bunBuffer,
        "subarray":         [.opt(.integer), .opt(.integer)] => .bunBuffer,
        "write":            [.string, .opt(.integer), .opt(.integer), .opt(.string)] => .integer,
        "fill":             [.jsAnything, .opt(.integer), .opt(.integer), .opt(.string)] => .bunBuffer,
        "indexOf":          [.jsAnything, .opt(.integer), .opt(.string)] => .integer,
        "lastIndexOf":      [.jsAnything, .opt(.integer), .opt(.string)] => .integer,
        "includes":         [.jsAnything, .opt(.integer), .opt(.string)] => .boolean,
        "swap16":           [] => .bunBuffer,
        "swap32":           [] => .bunBuffer,
        "swap64":           [] => .bunBuffer,
        "readInt8":         [.opt(.integer)] => .integer,
        "readUInt8":        [.opt(.integer)] => .integer,
        "readInt16BE":      [.opt(.integer)] => .integer,
        "readInt16LE":      [.opt(.integer)] => .integer,
        "readUInt16BE":     [.opt(.integer)] => .integer,
        "readUInt16LE":     [.opt(.integer)] => .integer,
        "readInt32BE":      [.opt(.integer)] => .integer,
        "readInt32LE":      [.opt(.integer)] => .integer,
        "readUInt32BE":     [.opt(.integer)] => .integer,
        "readUInt32LE":     [.opt(.integer)] => .integer,
        "readFloatBE":      [.opt(.integer)] => .float,
        "readFloatLE":      [.opt(.integer)] => .float,
        "readDoubleBE":     [.opt(.integer)] => .float,
        "readDoubleLE":     [.opt(.integer)] => .float,
        "readBigInt64BE":   [.opt(.integer)] => .bigint,
        "readBigInt64LE":   [.opt(.integer)] => .bigint,
        "readBigUInt64BE":  [.opt(.integer)] => .bigint,
        "readBigUInt64LE":  [.opt(.integer)] => .bigint,
        "writeInt8":        [.integer, .opt(.integer)] => .integer,
        "writeUInt8":       [.integer, .opt(.integer)] => .integer,
        "writeInt16BE":     [.integer, .opt(.integer)] => .integer,
        "writeInt16LE":     [.integer, .opt(.integer)] => .integer,
        "writeUInt16BE":    [.integer, .opt(.integer)] => .integer,
        "writeUInt16LE":    [.integer, .opt(.integer)] => .integer,
        "writeInt32BE":     [.integer, .opt(.integer)] => .integer,
        "writeInt32LE":     [.integer, .opt(.integer)] => .integer,
        "writeUInt32BE":    [.integer, .opt(.integer)] => .integer,
        "writeUInt32LE":    [.integer, .opt(.integer)] => .integer,
        "writeFloatBE":     [.float, .opt(.integer)] => .integer,
        "writeFloatLE":     [.float, .opt(.integer)] => .integer,
        "writeDoubleBE":    [.float, .opt(.integer)] => .integer,
        "writeDoubleLE":    [.float, .opt(.integer)] => .integer,
        "writeBigInt64BE":  [.bigint, .opt(.integer)] => .integer,
        "writeBigInt64LE":  [.bigint, .opt(.integer)] => .integer,
        "writeBigUInt64BE": [.bigint, .opt(.integer)] => .integer,
        "writeBigUInt64LE": [.bigint, .opt(.integer)] => .integer,
    ]
)

public let bunTextEncoderGroup = ObjectGroup(
    name: "TextEncoder",
    instanceType: .bunTextEncoder,
    properties: [
        "encoding": .string,
    ],
    methods: [
        "encode":     [.opt(.string)] => .object(),  // Returns Uint8Array
        "encodeInto": [.string, .object()] => .object(),  // Returns {read, written}
    ]
)

public let bunTextDecoderGroup = ObjectGroup(
    name: "TextDecoder",
    instanceType: .bunTextDecoder,
    properties: [
        "encoding":  .string,
        "fatal":     .boolean,
        "ignoreBOM": .boolean,
    ],
    methods: [
        "decode": [.opt(.object()), .opt(.object())] => .string,
    ]
)

public let bunURLGroup = ObjectGroup(
    name: "URL",
    instanceType: .bunURL,
    properties: [
        "href":         .string,
        "origin":       .string,
        "protocol":     .string,
        "username":     .string,
        "password":     .string,
        "host":         .string,
        "hostname":     .string,
        "port":         .string,
        "pathname":     .string,
        "search":       .string,
        "searchParams": .bunURLSearchParams,
        "hash":         .string,
    ],
    methods: [
        "toString": [] => .string,
        "toJSON":   [] => .string,
    ]
)

public let bunURLSearchParamsGroup = ObjectGroup(
    name: "URLSearchParams",
    instanceType: .bunURLSearchParams,
    properties: [
        "size": .integer,
    ],
    methods: [
        "append":  [.string, .string] => .undefined,
        "delete":  [.string, .opt(.string)] => .undefined,
        "get":     [.string] => (.string | .undefined),
        "getAll":  [.string] => .jsArray,
        "has":     [.string, .opt(.string)] => .boolean,
        "set":     [.string, .string] => .undefined,
        "sort":    [] => .undefined,
        "toString": [] => .string,
        "entries": [] => .object(),
        "keys":    [] => .object(),
        "values":  [] => .object(),
        "forEach": [.function()] => .undefined,
    ]
)

public let bunFormDataGroup = ObjectGroup(
    name: "FormData",
    instanceType: .bunFormData,
    properties: [:],
    methods: [
        "append":  [.string, .jsAnything, .opt(.string)] => .undefined,
        "delete":  [.string] => .undefined,
        "get":     [.string] => .jsAnything,
        "getAll":  [.string] => .jsArray,
        "has":     [.string] => .boolean,
        "set":     [.string, .jsAnything, .opt(.string)] => .undefined,
        "entries": [] => .object(),
        "keys":    [] => .object(),
        "values":  [] => .object(),
        "forEach": [.function()] => .undefined,
    ]
)

public let bunBlobGroup = ObjectGroup(
    name: "Blob",
    instanceType: .bunBlob,
    properties: [
        "size": .integer,
        "type": .string,
    ],
    methods: [
        "slice":       [.opt(.integer), .opt(.integer), .opt(.string)] => .bunBlob,
        "stream":      [] => .object(),
        "text":        [] => .jsPromise,
        "arrayBuffer": [] => .jsPromise,
    ]
)

// MARK: - Bun Code Generators

// Generator that exercises Bun hash APIs with specific algorithm strings
public let BunHashGenerator = CodeGenerator("BunHashGenerator") { b in
    let algorithms = ["md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512-256", "blake2b256", "blake2b512"]
    let digestFormats = ["hex", "base64"]

    let algorithm = b.loadString(algorithms.randomElement()!)
    let data = b.loadString(b.randomString())

    // Create a CryptoHasher with specific algorithm
    let hasherConstructor = b.createNamedVariable(forBuiltin: "CryptoHasher")
    let hasher = b.construct(hasherConstructor, withArgs: [algorithm])
    b.callMethod("update", on: hasher, withArgs: [data])

    let digestFormat = b.loadString(digestFormats.randomElement()!)
    b.callMethod("digest", on: hasher, withArgs: [digestFormat])
}

// Generator that exercises Buffer encoding APIs
public let BunBufferEncodingGenerator = CodeGenerator("BunBufferEncodingGenerator") { b in
    let encodings = ["utf8", "utf-8", "utf16le", "base64", "base64url", "latin1", "hex", "ascii"]

    let encoding = b.loadString(encodings.randomElement()!)
    let data = b.loadString(b.randomString())

    let bufferConstructor = b.createNamedVariable(forBuiltin: "Buffer")

    // Buffer.from with encoding
    b.callMethod("from", on: bufferConstructor, withArgs: [data, encoding])
}

// Helper to generate random color strings
fileprivate func randomColorString() -> String {
    let r = Int.random(in: 0...255)
    let g = Int.random(in: 0...255)
    let b = Int.random(in: 0...255)
    let a = Double.random(in: 0...1)
    let h = Int.random(in: 0...360)
    let s = Int.random(in: 0...100)
    let l = Int.random(in: 0...100)

    let namedColors = ["red", "blue", "green", "yellow", "cyan", "magenta", "white", "black",
                       "orange", "purple", "pink", "brown", "gray", "grey", "lime", "navy",
                       "teal", "olive", "maroon", "aqua", "fuchsia", "silver", "transparent"]

    switch Int.random(in: 0...11) {
    case 0:  // Named color
        return namedColors.randomElement()!
    case 1:  // 3-digit hex
        return "#\(String(format: "%X", Int.random(in: 0...15)))\(String(format: "%X", Int.random(in: 0...15)))\(String(format: "%X", Int.random(in: 0...15)))"
    case 2:  // 6-digit hex
        return "#\(String(format: "%02X", r))\(String(format: "%02X", g))\(String(format: "%02X", b))"
    case 3:  // 8-digit hex with alpha
        return "#\(String(format: "%02X", r))\(String(format: "%02X", g))\(String(format: "%02X", b))\(String(format: "%02X", Int(a * 255)))"
    case 4:  // rgb()
        return "rgb(\(r), \(g), \(b))"
    case 5:  // rgba()
        return "rgba(\(r), \(g), \(b), \(String(format: "%.2f", a)))"
    case 6:  // hsl()
        return "hsl(\(h), \(s)%, \(l)%)"
    case 7:  // hsla()
        return "hsla(\(h), \(s)%, \(l)%, \(String(format: "%.2f", a)))"
    case 8:  // oklch()
        let lch_l = Double.random(in: 0...1)
        let lch_c = Double.random(in: 0...0.4)
        let lch_h = Double.random(in: 0...360)
        return "oklch(\(String(format: "%.3f", lch_l)) \(String(format: "%.3f", lch_c)) \(String(format: "%.1f", lch_h)))"
    case 9:  // lab()
        let lab_l = Double.random(in: 0...100)
        let lab_a = Double.random(in: -128...128)
        let lab_b = Double.random(in: -128...128)
        return "lab(\(String(format: "%.1f", lab_l))% \(String(format: "%.1f", lab_a)) \(String(format: "%.1f", lab_b)))"
    case 10: // Modern rgb with space syntax
        return "rgb(\(r) \(g) \(b) / \(String(format: "%.0f", a * 100))%)"
    default: // hwb()
        let w = Int.random(in: 0...100)
        let bk = Int.random(in: 0...(100 - w))
        return "hwb(\(h) \(w)% \(bk)%)"
    }
}

// Generator that exercises Bun.color with format strings
public let BunColorGenerator = CodeGenerator("BunColorGenerator") { b in
    let formats = ["css", "ansi", "ansi-16", "ansi-256", "ansi-16m", "rgb", "rgba", "hsl", "hex", "HEX", "{rgb}", "{rgba}", "[rgb]", "[rgba]"]

    let color = b.loadString(randomColorString())
    let format = b.loadString(formats.randomElement()!)

    let bun = b.createNamedVariable(forBuiltin: "Bun")
    b.callMethod("color", on: bun, withArgs: [color, format])
}

// Helper to generate safe URLs for fuzzing (no actual network I/O)
fileprivate func randomSafeUrl() -> String {
    switch Int.random(in: 0...7) {
    case 0:  // data: URL with text (pre-encoded)
        return "data:text/plain,Hello%20World%20\(Int.random(in: 0...1000))"
    case 1:  // data: URL with JSON (pre-encoded)
        return "data:application/json,{%22key%22:\(Int.random(in: 0...1000))}"
    case 2:  // data: URL with base64 text
        return "data:text/plain;base64,SGVsbG8gV29ybGQ="  // "Hello World"
    case 3:  // data: URL with base64 JSON
        return "data:application/json;base64,eyJrZXkiOjEyM30="  // {"key":123}
    case 4:  // file: URL
        return "file:///dev/null"
    case 5:  // http URL to localhost (won't connect but tests URL parsing)
        return "http://localhost:\(Int.random(in: 1...65535))/path/\(Int.random(in: 0...1000))"
    case 6:  // https URL to localhost
        return "https://127.0.0.1:\(Int.random(in: 1...65535))/api/v\(Int.random(in: 1...3))/resource"
    default: // Various URL edge cases
        let edgeCases = [
            "http://[::1]/ipv6",
            "http://localhost/path?query=\(Int.random(in: 0...1000))&foo=bar",
            "http://localhost/path#fragment",
            "http://user:pass@localhost/auth",
            "http://localhost:8080/path/../normalized",
            "http://localhost/path%20with%20spaces",
        ]
        return edgeCases.randomElement()!
    }
}

// Helper to create random body for Request/Response
fileprivate func createRandomBody(_ b: ProgramBuilder) -> Variable {
    switch Int.random(in: 0...8) {
    case 0:  // String body (plain text)
        return b.loadString("Hello World \(Int.random(in: 0...1000))")

    case 1:  // String body (JSON)
        return b.loadString("{\"key\": \(Int.random(in: 0...1000)), \"nested\": {\"arr\": [1,2,3]}}")

    case 2:  // String body (HTML)
        return b.loadString("<html><body><h1>Test \(Int.random(in: 0...1000))</h1></body></html>")

    case 3:  // null body
        return b.loadNull()

    case 4:  // Blob body
        let blobConstructor = b.createNamedVariable(forBuiltin: "Blob")
        let content = b.createArray(with: [b.loadString("blob content \(Int.random(in: 0...1000))")])
        let options = b.createObject(with: ["type": b.loadString(["text/plain", "application/octet-stream", "application/json"].randomElement()!)])
        return b.construct(blobConstructor, withArgs: [content, options])

    case 5:  // ArrayBuffer via TextEncoder
        let encoderConstructor = b.createNamedVariable(forBuiltin: "TextEncoder")
        let encoder = b.construct(encoderConstructor)
        let encoded = b.callMethod("encode", on: encoder, withArgs: [b.loadString("encoded data \(Int.random(in: 0...1000))")])
        return encoded

    case 6:  // URLSearchParams body
        let paramsConstructor = b.createNamedVariable(forBuiltin: "URLSearchParams")
        let params = b.construct(paramsConstructor)
        b.callMethod("set", on: params, withArgs: [b.loadString("key1"), b.loadString("value1")])
        b.callMethod("set", on: params, withArgs: [b.loadString("key2"), b.loadString("\(Int.random(in: 0...1000))")])
        return params

    case 7:  // FormData body
        let formDataConstructor = b.createNamedVariable(forBuiltin: "FormData")
        let formData = b.construct(formDataConstructor)
        b.callMethod("set", on: formData, withArgs: [b.loadString("field1"), b.loadString("value1")])
        b.callMethod("set", on: formData, withArgs: [b.loadString("field2"), b.loadString("\(Int.random(in: 0...1000))")])
        return formData

    default:  // Uint8Array body
        let uint8Constructor = b.createNamedVariable(forBuiltin: "Uint8Array")
        let bytes = (0..<Int.random(in: 1...32)).map { _ in b.loadInt(Int64.random(in: 0...255)) }
        let arr = b.createArray(with: bytes)
        return b.construct(uint8Constructor, withArgs: [arr])
    }
}

// Generator that exercises fetch/Request/Response APIs
public let BunFetchGenerator = CodeGenerator("BunFetchGenerator") { b in
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    let modes = ["cors", "no-cors", "same-origin"]
    let credentials = ["omit", "same-origin", "include"]
    let caches = ["default", "no-store", "reload", "no-cache", "force-cache"]
    let redirects = ["follow", "error", "manual"]
    let contentTypes = [
        "text/plain", "text/html", "text/css", "text/javascript",
        "application/json", "application/xml", "application/octet-stream",
        "application/x-www-form-urlencoded", "multipart/form-data",
        "image/png", "image/jpeg", "image/gif", "image/webp",
    ]

    let url = b.loadString(randomSafeUrl())

    // Sometimes create a Request object with body
    if Bool.random() {
        // Build request options with random properties included/excluded
        var optionsDict: [String: Variable] = [:]

        // Randomly include method
        if Bool.random() {
            optionsDict["method"] = b.loadString(methods.randomElement()!)
        }

        // Randomly include headers
        if Bool.random() {
            let headersConstructor = b.createNamedVariable(forBuiltin: "Headers")
            let headers = b.construct(headersConstructor)
            if Bool.random() {
                b.callMethod("set", on: headers, withArgs: [b.loadString("Content-Type"), b.loadString(contentTypes.randomElement()!)])
            }
            if Bool.random() {
                b.callMethod("set", on: headers, withArgs: [b.loadString("X-Custom-Header"), b.loadString(b.randomString())])
            }
            if Bool.random() {
                b.callMethod("set", on: headers, withArgs: [b.loadString("Accept"), b.loadString(["*/*", "application/json", "text/html"].randomElement()!)])
            }
            optionsDict["headers"] = headers
        }

        // Randomly include other options
        if Bool.random() { optionsDict["mode"] = b.loadString(modes.randomElement()!) }
        if Bool.random() { optionsDict["credentials"] = b.loadString(credentials.randomElement()!) }
        if Bool.random() { optionsDict["cache"] = b.loadString(caches.randomElement()!) }
        if Bool.random() { optionsDict["redirect"] = b.loadString(redirects.randomElement()!) }
        if Bool.random() { optionsDict["referrer"] = b.loadString(["", "about:client", "http://localhost/"].randomElement()!) }
        if Bool.random() { optionsDict["referrerPolicy"] = b.loadString(["no-referrer", "origin", "same-origin", "strict-origin"].randomElement()!) }
        if Bool.random() { optionsDict["integrity"] = b.loadString("sha256-\(Int.random(in: 0...999999))") }
        if Bool.random() { optionsDict["keepalive"] = b.loadBool(Bool.random()) }

        // Add body randomly
        if Bool.random() {
            optionsDict["body"] = createRandomBody(b)
        }

        // Shuffle the order of properties
        let shuffledKeys = optionsDict.keys.shuffled()
        var shuffledOptions: [String: Variable] = [:]
        for key in shuffledKeys {
            shuffledOptions[key] = optionsDict[key]
        }

        let requestConstructor = b.createNamedVariable(forBuiltin: "Request")
        let request: Variable
        if optionsDict.isEmpty && Bool.random() {
            request = b.construct(requestConstructor, withArgs: [url])
        } else {
            let options = b.createObject(with: shuffledOptions)
            request = b.construct(requestConstructor, withArgs: [url, options])
        }

        // Access request properties
        b.getProperty("method", of: request)
        b.getProperty("url", of: request)
        b.getProperty("headers", of: request)
        b.callMethod("clone", on: request)

        // Try to read body
        if Bool.random() {
            b.callMethod("text", on: request)
        } else if Bool.random() {
            b.callMethod("json", on: request)
        } else if Bool.random() {
            b.callMethod("arrayBuffer", on: request)
        } else if Bool.random() {
            b.callMethod("blob", on: request)
        }
    }

    // Create Response with random body type
    let responseConstructor = b.createNamedVariable(forBuiltin: "Response")
    let body = createRandomBody(b)

    // Build response options with random properties included/excluded
    var responseOptionsDict: [String: Variable] = [:]

    // Randomly include status
    if Bool.random() {
        let statuses = [200, 201, 202, 204, 206, 301, 302, 303, 304, 307, 308, 400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 429, 500, 501, 502, 503, 504]
        responseOptionsDict["status"] = b.loadInt(Int64(statuses.randomElement()!))
    }

    // Randomly include statusText
    if Bool.random() {
        responseOptionsDict["statusText"] = b.loadString(["OK", "Created", "Accepted", "No Content", "Moved", "Found", "Bad Request", "Unauthorized", "Forbidden", "Not Found", "Server Error"].randomElement()!)
    }

    // Randomly include headers
    if Bool.random() {
        let responseHeaders = b.createNamedVariable(forBuiltin: "Headers")
        let respHeaders = b.construct(responseHeaders)
        if Bool.random() {
            b.callMethod("set", on: respHeaders, withArgs: [b.loadString("Content-Type"), b.loadString(contentTypes.randomElement()!)])
        }
        if Bool.random() {
            b.callMethod("set", on: respHeaders, withArgs: [b.loadString("X-Response-ID"), b.loadString("\(Int.random(in: 0...99999))")])
        }
        if Bool.random() {
            b.callMethod("set", on: respHeaders, withArgs: [b.loadString("Cache-Control"), b.loadString(["no-cache", "no-store", "max-age=3600", "public", "private"].randomElement()!)])
        }
        responseOptionsDict["headers"] = respHeaders
    }

    // Shuffle the order of properties by recreating dict with shuffled keys
    let shuffledKeys = responseOptionsDict.keys.shuffled()
    var shuffledOptions: [String: Variable] = [:]
    for key in shuffledKeys {
        shuffledOptions[key] = responseOptionsDict[key]
    }

    // Sometimes pass no options at all, sometimes pass empty object
    let response: Variable
    if responseOptionsDict.isEmpty && Bool.random() {
        response = b.construct(responseConstructor, withArgs: [body])
    } else {
        let responseOptions = b.createObject(with: shuffledOptions)
        response = b.construct(responseConstructor, withArgs: [body, responseOptions])
    }

    // Access response properties and methods
    b.getProperty("ok", of: response)
    b.getProperty("status", of: response)
    b.getProperty("statusText", of: response)
    b.getProperty("headers", of: response)
    b.getProperty("bodyUsed", of: response)

    // Clone and read body in different ways
    let cloned = b.callMethod("clone", on: response)

    switch Int.random(in: 0...4) {
    case 0: b.callMethod("text", on: cloned)
    case 1: b.callMethod("json", on: cloned)
    case 2: b.callMethod("arrayBuffer", on: cloned)
    case 3: b.callMethod("blob", on: cloned)
    default: b.callMethod("formData", on: cloned)
    }

    // Response static methods
    if Bool.random() {
        let jsonData = b.createObject(with: [
            "key": b.loadString("value"),
            "number": b.loadInt(Int64.random(in: -1000...1000)),
            "array": b.createArray(with: [b.loadInt(1), b.loadInt(2), b.loadInt(3)]),
        ])
        b.callMethod("json", on: responseConstructor, withArgs: [jsonData])
    }

    if Bool.random() {
        b.callMethod("redirect", on: responseConstructor, withArgs: [b.loadString("http://localhost/redirect"), b.loadInt(Int64([301, 302, 303, 307, 308].randomElement()!))])
    }

    if Bool.random() {
        b.callMethod("error", on: responseConstructor)
    }
}

// MARK: - Bun Profile

let bunProfile = Profile(
    processArgs: { randomize in ["fuzzilli"] },


    processEnv: [
        "ASAN_OPTIONS": "allow_user_segv_handler=1:allocator_may_return_null=1:abort_on_error=1:symbolize=false:redzone=128:detect_leaks=0",
        "UBSAN_OPTIONS": "abort_on_error=1:symbolize=false:redzone=128",
        "BUN_DEBUG_QUIET_LOGS": "1",
    ],

    maxExecsBeforeRespawn: 1000,

    timeout: 2500,

    codePrefix: """
                delete globalThis.Loader;
                Bun.generateHeapSnapshot = console.profile = console.profileEnd = process.abort = () => {};
                """,

    codeSuffix: """
                Bun.gc(true);
                """,

    ecmaVersion: ECMAScriptVersion.es6,

    startupTests: [
        // Check that the fuzzilli integration is available.
        ("fuzzilli('FUZZILLI_PRINT', 'test')", .shouldSucceed),

        // Check that common crash types are detected (using integer crash codes like V8)
        ("fuzzilli('FUZZILLI_CRASH', 0)", .shouldCrash),  // IMMEDIATE_CRASH
        ("fuzzilli('FUZZILLI_CRASH', 1)", .shouldCrash),  // CHECK failure (__builtin_trap)
        ("fuzzilli('FUZZILLI_CRASH', 2)", .shouldCrash),  // DCHECK failure (assert)
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),  // Wild write (heap overflow)
        ("fuzzilli('FUZZILLI_CRASH', 4)", .shouldCrash),  // Use-after-free
        ("fuzzilli('FUZZILLI_CRASH', 5)", .shouldCrash),  // Null pointer dereference
        ("fuzzilli('FUZZILLI_CRASH', 8)", .shouldSucceed), // Verify DEBUG/ASAN is enabled
    ],

    additionalCodeGenerators: [
        (BunHashGenerator,           10),
        (BunBufferEncodingGenerator, 10),
        (BunColorGenerator,           5),
        (BunFetchGenerator,          10),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([]),

    disabledCodeGenerators: [],

    disabledMutators: [],

    additionalBuiltins: [
        // Bun-specific globals
        "Bun"               : .object(),
        "gc"                : .function([] => .undefined),

        // Common Node.js globals that Bun provides
        "process"           : .object(),
        "Buffer"            : .constructor([.jsAnything] => .bunBuffer),

        // Web APIs
        "fetch"             : .function([.jsAnything, .opt(.object())] => .jsPromise),
        "Headers"           : .constructor([.opt(.jsAnything)] => .bunHeaders),
        "Request"           : .constructor([.jsAnything, .opt(.object())] => .bunRequest),
        "Response"          : .constructor([.opt(.jsAnything), .opt(.object())] => .bunResponse),
        "Response.json"     : .function([.jsAnything, .opt(.object())] => .bunResponse),
        "Response.redirect" : .function([.string, .opt(.integer)] => .bunResponse),
        "Response.error"    : .function([] => .bunResponse),
        "URL"               : .constructor([.string, .opt(.string)] => .bunURL),
        "URLSearchParams"   : .constructor([.opt(.jsAnything)] => .bunURLSearchParams),
        "FormData"          : .constructor([] => .bunFormData),
        "Blob"              : .constructor([.opt(.object()), .opt(.object())] => .bunBlob),
        "TextEncoder"       : .constructor([] => .bunTextEncoder),
        "TextDecoder"       : .constructor([.opt(.string), .opt(.object())] => .bunTextDecoder),
        "atob"              : .function([.string] => .string),
        "btoa"              : .function([.string] => .string),
        // Buffer.from(array | arrayBuffer | buffer | string | object, [offsetOrEncoding], [length])
        "Buffer.from"       : .function([.jsAnything, .opt(.jsAnything), .opt(.integer)] => .bunBuffer),
        // Buffer.alloc(size[, fill[, encoding]])
        "Buffer.alloc"      : .function([.integer, .opt(.jsAnything), .opt(.string)] => .bunBuffer),
        "Buffer.allocUnsafe" : .function([.integer] => .bunBuffer),
        "Buffer.allocUnsafeSlow" : .function([.integer] => .bunBuffer),
        "Buffer.isBuffer"   : .function([.jsAnything] => .boolean),
        "Buffer.isEncoding" : .function([.string] => .boolean),
        // Buffer.byteLength(string | buffer | arrayBuffer | ..., [encoding])
        "Buffer.byteLength" : .function([.jsAnything, .opt(.string)] => .integer),
        "Buffer.compare"    : .function([.plain(.bunBuffer), .plain(.bunBuffer)] => .integer),
        // Buffer.concat(list[, totalLength])
        "Buffer.concat"     : .function([.object(), .opt(.integer)] => .bunBuffer),
        // Buffer.copyBytesFrom(view[, offset[, length]])
        "Buffer.copyBytesFrom" : .function([.object(), .opt(.integer), .opt(.integer)] => .bunBuffer),
        "global"            : .object(),

        // Bun constructors
        "CryptoHasher"      : .constructor([.string, .opt(.jsAnything)] => .bunCryptoHasher),
        "Transpiler"        : .constructor([.opt(.object())] => .bunTranspiler),
        "Glob"              : .constructor([.string, .opt(.object())] => .bunGlob),
        "HTMLRewriter"      : .constructor([] => .htmlRewriter),

        // Bun hash constructors (shortcuts for specific algorithms)
        // These are constructor objects with a static .hash method
        "Bun.MD4"           : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.MD5"           : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.SHA1"          : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.SHA224"        : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.SHA256"        : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.SHA384"        : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.SHA512"        : .bunHashConstructor + .constructor([] => .bunCryptoHasher),
        "Bun.SHA512_256"    : .bunHashConstructor + .constructor([] => .bunCryptoHasher),

        // Bun utility methods (non-blocking, non-IO)
        "Bun.hash"          : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.wyhash"   : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.crc32"    : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.adler32"  : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.cityHash32" : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.cityHash64" : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.xxHash32"   : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.xxHash64"   : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.xxHash3"    : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.murmur32v3" : .function([.jsAnything, .opt(.integer)] => .integer),
        "Bun.hash.murmur64v2" : .function([.jsAnything, .opt(.integer)] => .integer),

        // String utilities
        "Bun.escapeHTML"    : .function([.string] => .string),
        "Bun.stringWidth"   : .function([.string, .opt(.object())] => .integer),
        "Bun.stripANSI"     : .function([.string] => .string),
        "Bun.inspect"       : .function([.jsAnything, .opt(.object())] => .string),
        "Bun.color"         : .function([.string, .opt(.string)] => .jsAnything),
        "Bun.shellEscape"   : .function([.string] => .string),

        // Comparison
        "Bun.deepEquals"    : .function([.jsAnything, .jsAnything, .opt(.boolean)] => .boolean),
        "Bun.deepMatch"     : .function([.jsAnything, .jsAnything] => .boolean),

        // Semver utilities
        "Bun.semver.satisfies" : .function([.string, .string] => .boolean),
        "Bun.semver.order"     : .function([.string, .string] => .integer),

        // UUID generation
        "Bun.randomUUIDv7"  : .function([.opt(.string), .opt(.integer)] => .string),
        "Bun.randomUUIDv5"  : .function([.string, .string, .opt(.string)] => .string),

        // Path utilities
        "Bun.fileURLToPath" : .function([.string] => .string),
        "Bun.pathToFileURL" : .function([.string] => .string),
        "Bun.which"         : .function([.string, .opt(.object())] => .jsAnything),
        "Bun.resolveSync"   : .function([.string, .string] => .string),

        // Promise inspection
        "Bun.peek"          : .function([.plain(.jsPromise)] => .jsAnything),
        "Bun.peek.status"   : .function([.plain(.jsPromise)] => .string),

        // Password hashing
        "Bun.password"      : .bunPasswordHasher,

        // Timing
        "Bun.nanoseconds"   : .function([] => .integer),
        "Bun.sleepSync"     : .function([.number] => .undefined),

        // Compression (synchronous)
        "Bun.gzipSync"      : .function([.jsAnything, .opt(.object())] => .object()),
        "Bun.gunzipSync"    : .function([.jsAnything] => .object()),
        "Bun.deflateSync"   : .function([.jsAnything, .opt(.object())] => .object()),
        "Bun.inflateSync"   : .function([.jsAnything] => .object()),
        "Bun.zstdCompressSync"   : .function([.jsAnything, .opt(.object())] => .object()),
        "Bun.zstdDecompressSync" : .function([.jsAnything] => .object()),

        // Bun metadata properties
        "Bun.version"       : .string,
        "Bun.revision"      : .string,
        "Bun.enableANSIColors" : .boolean,
        "Bun.isMainThread"  : .boolean,

        // Buffer utilities
        "Bun.concatArrayBuffers" : .function([.object(), .opt(.integer), .opt(.boolean)] => .object()),
        "Bun.indexOfLine"   : .function([.object(), .opt(.integer)] => .integer),
        "Bun.allocUnsafe"   : .function([.integer] => .object()),

        // SHA function
        "Bun.sha"           : .function([.jsAnything, .opt(.string)] => .object()),

        // Memory management
        "Bun.shrink"        : .function([] => .undefined),

        // Parsers
        "Bun.TOML"          : .bunTOML,
        "Bun.YAML"          : .bunYAML,

        // Fuzzilli integration
        "fuzzilli"          : .function([.string, .jsAnything] => .undefined),
    ],

    additionalObjectGroups: [
        bunCryptoHasherGroup,
        bunTranspilerGroup,
        bunPasswordHasherGroup,
        bunGlobGroup,
        htmlRewriterGroup,
        htmlRewriterElementGroup,
        htmlRewriterTextGroup,
        htmlRewriterCommentGroup,
        bunTOMLGroup,
        bunYAMLGroup,
        bunHashConstructorGroup,
        bunHashOptions,
        bunColorOptions,
        bunHeadersGroup,
        bunRequestGroup,
        bunResponseGroup,
        bunBufferGroup,
        bunTextEncoderGroup,
        bunTextDecoderGroup,
        bunURLGroup,
        bunURLSearchParamsGroup,
        bunFormDataGroup,
        bunBlobGroup,
    ],

    optionalPostProcessor: nil
)
