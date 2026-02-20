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

    // BunJSON5 - JSON5 parser
    static let bunJSON5 = ILType.object(
        ofGroup: "BunJSON5",
        withProperties: [],
        withMethods: ["parse"]
    )

    // BunJSONC - JSONC parser
    static let bunJSONC = ILType.object(
        ofGroup: "BunJSONC",
        withProperties: [],
        withMethods: ["parse"]
    )

    // BunJSONL - JSONL parser/stringifier
    static let bunJSONL = ILType.object(
        ofGroup: "BunJSONL",
        withProperties: [],
        withMethods: ["parse", "stringify"]
    )

    // BunFile - File handle returned by Bun.file()
    static let bunFile = ILType.object(
        ofGroup: "BunFile",
        withProperties: ["size", "type", "name"],
        withMethods: ["text", "json", "arrayBuffer", "stream", "slice", "exists", "writer"]
    )

    // BunSubprocess - Result of Bun.spawn()
    static let bunSubprocess = ILType.object(
        ofGroup: "BunSubprocess",
        withProperties: ["pid", "exitCode", "signalCode", "stdin", "stdout", "stderr", "exited"],
        withMethods: ["kill", "ref", "unref"]
    )

    // BunSyncSubprocess - Result of Bun.spawnSync()
    static let bunSyncSubprocess = ILType.object(
        ofGroup: "BunSyncSubprocess",
        withProperties: ["exitCode", "signalCode", "stdout", "stderr", "success"],
        withMethods: []
    )

    // BunTCPSocket
    static let bunTCPSocket = ILType.object(
        ofGroup: "BunTCPSocket",
        withProperties: ["data", "readyState", "remoteAddress", "localPort"],
        withMethods: ["write", "end", "close", "terminate", "ref", "unref", "reload", "flush"]
    )

    // BunFileSystemRouter
    static let bunFileSystemRouter = ILType.object(
        ofGroup: "BunFileSystemRouter",
        withProperties: ["routes"],
        withMethods: ["match", "reload"]
    )

    // BunArchive
    static let bunArchive = ILType.object(
        ofGroup: "BunArchive",
        withProperties: ["count"],
        withMethods: ["extract", "readFile", "entries", "close"]
    )

    // BunServer - result of Bun.serve()
    static let bunServer = ILType.object(
        ofGroup: "BunServer",
        withProperties: ["port", "hostname", "url", "development"],
        withMethods: ["stop", "reload", "ref", "unref", "requestIP", "upgrade"]
    )

    // BunArrayBufferSink
    static let bunArrayBufferSink = ILType.object(
        ofGroup: "BunArrayBufferSink",
        withProperties: [],
        withMethods: ["write", "flush", "end", "start"]
    )

    // BunCookie
    static let bunCookie = ILType.object(
        ofGroup: "BunCookie",
        withProperties: ["name", "value", "domain", "path", "expires", "secure", "httpOnly", "sameSite", "maxAge"],
        withMethods: ["toString", "toJSON"]
    )

    // BunCookieMap
    static let bunCookieMap = ILType.object(
        ofGroup: "BunCookieMap",
        withProperties: [],
        withMethods: ["get", "set", "delete", "has", "entries", "keys", "values", "toJSON"]
    )

    // BunTerminal
    static let bunTerminal = ILType.object(
        ofGroup: "BunTerminal",
        withProperties: ["columns", "rows"],
        withMethods: ["write", "clearLine", "cursorTo", "moveCursor"]
    )

    // BunS3Client
    static let bunS3Client = ILType.object(
        ofGroup: "BunS3Client",
        withProperties: [],
        withMethods: ["file", "write", "exists", "delete", "size", "stat", "presign", "unlink"]
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

public let bunJSON5Group = ObjectGroup(
    name: "BunJSON5",
    instanceType: .bunJSON5,
    properties: [:],
    methods: [
        "parse": [.string] => .jsAnything,
    ]
)

public let bunJSONCGroup = ObjectGroup(
    name: "BunJSONC",
    instanceType: .bunJSONC,
    properties: [:],
    methods: [
        "parse": [.string] => .jsAnything,
    ]
)

public let bunJSONLGroup = ObjectGroup(
    name: "BunJSONL",
    instanceType: .bunJSONL,
    properties: [:],
    methods: [
        "parse": [.string] => .jsAnything,
        "stringify": [.jsAnything] => .string,
    ]
)

public let bunFileGroup = ObjectGroup(
    name: "BunFile",
    instanceType: .bunFile,
    properties: [
        "size": .integer,
        "type": .string,
        "name": .string,
    ],
    methods: [
        "text":        [] => .jsPromise,
        "json":        [] => .jsPromise,
        "arrayBuffer": [] => .jsPromise,
        "stream":      [] => .jsAnything,
        "slice":       [.opt(.integer), .opt(.integer)] => .bunFile,
        "exists":      [] => .jsPromise,
        "writer":      [.opt(.object())] => .jsAnything,
    ]
)

public let bunSubprocessGroup = ObjectGroup(
    name: "BunSubprocess",
    instanceType: .bunSubprocess,
    properties: [
        "pid":        .integer,
        "exitCode":   .integer | .undefined,
        "signalCode": .string | .undefined,
        "stdin":      .jsAnything,
        "stdout":     .jsAnything,
        "stderr":     .jsAnything,
        "exited":     .jsPromise,
    ],
    methods: [
        "kill":  [.opt(.integer)] => .undefined,
        "ref":   [] => .undefined,
        "unref": [] => .undefined,
    ]
)

public let bunSyncSubprocessGroup = ObjectGroup(
    name: "BunSyncSubprocess",
    instanceType: .bunSyncSubprocess,
    properties: [
        "exitCode":   .integer,
        "signalCode": .string | .undefined,
        "stdout":     .jsAnything,
        "stderr":     .jsAnything,
        "success":    .boolean,
    ],
    methods: [:]
)

public let bunFileSystemRouterGroup = ObjectGroup(
    name: "BunFileSystemRouter",
    instanceType: .bunFileSystemRouter,
    properties: [
        "routes": .object(),
    ],
    methods: [
        "match":  [.string] => .jsAnything,
        "reload": [] => .undefined,
    ]
)

public let bunArchiveGroup = ObjectGroup(
    name: "BunArchive",
    instanceType: .bunArchive,
    properties: [
        "count": .integer,
    ],
    methods: [
        "extract":  [.opt(.string)] => .jsPromise,
        "readFile": [.string] => .jsPromise,
        "entries":  [] => .jsAnything,
        "close":    [] => .undefined,
    ]
)

public let bunServerGroup = ObjectGroup(
    name: "BunServer",
    instanceType: .bunServer,
    properties: [
        "port":        .integer,
        "hostname":    .string,
        "url":         .string,
        "development": .boolean,
    ],
    methods: [
        "stop":      [.opt(.boolean)] => .undefined,
        "reload":    [.object()] => .undefined,
        "ref":       [] => .undefined,
        "unref":     [] => .undefined,
        "requestIP": [.jsAnything] => .jsAnything,
    ]
)

public let bunArrayBufferSinkGroup = ObjectGroup(
    name: "BunArrayBufferSink",
    instanceType: .bunArrayBufferSink,
    properties: [:],
    methods: [
        "write": [.jsAnything] => .integer,
        "flush": [] => .jsAnything,
        "end":   [] => .jsAnything,
        "start": [.opt(.object())] => .undefined,
    ]
)

public let bunCookieGroup = ObjectGroup(
    name: "BunCookie",
    instanceType: .bunCookie,
    properties: [
        "name":     .string,
        "value":    .string,
        "domain":   .string,
        "path":     .string,
        "secure":   .boolean,
        "httpOnly": .boolean,
        "sameSite": .string,
    ],
    methods: [
        "toString": [] => .string,
        "toJSON":   [] => .object(),
    ]
)

public let bunCookieMapGroup = ObjectGroup(
    name: "BunCookieMap",
    instanceType: .bunCookieMap,
    properties: [:],
    methods: [
        "get":     [.string] => .jsAnything,
        "set":     [.string, .string, .opt(.object())] => .undefined,
        "delete":  [.string] => .boolean,
        "has":     [.string] => .boolean,
        "entries": [] => .jsAnything,
        "keys":    [] => .jsAnything,
        "values":  [] => .jsAnything,
        "toJSON":  [] => .object(),
    ]
)

// MARK: - Bun Code Generators

// Generator that safely exercises Bun.spawn with harmless commands
public let BunSpawnGenerator = CodeGenerator("BunSpawnGenerator") { b in
    let commands: [(String, [String])] = [
        ("echo", ["hello"]),
        ("true", []),
        ("printf", ["%s", "test"]),
        ("cat", ["/dev/null"]),
    ]
    let (cmd, args) = commands.randomElement()!

    let cmdArray = b.createArray(with: ([cmd] + args).map { b.loadString($0) })
    let bun = b.createNamedVariable(forBuiltin: "Bun")

    if Bool.random() {
        // spawnSync
        let result = b.callMethod("spawnSync", on: bun, withArgs: [cmdArray])
        b.getProperty("stdout", of: result)
        b.getProperty("exitCode", of: result)
    } else {
        // spawn
        let proc = b.callMethod("spawn", on: bun, withArgs: [cmdArray])
        b.getProperty("pid", of: proc)
        b.getProperty("exited", of: proc)
    }
}

// Generator that exercises Bun.file() with safe paths
public let BunFileGenerator = CodeGenerator("BunFileGenerator") { b in
    let paths = [
        "/dev/null",
        "/tmp/fuzzilli-test-\(Int.random(in: 0...9999))",
        "/proc/self/status",
    ]
    let path = b.loadString(paths.randomElement()!)
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let file = b.callMethod("file", on: bun, withArgs: [path])

    switch Int.random(in: 0...4) {
    case 0: b.callMethod("text", on: file)
    case 1: b.callMethod("json", on: file)
    case 2: b.callMethod("arrayBuffer", on: file)
    case 3: b.callMethod("exists", on: file)
    default: b.getProperty("size", of: file)
    }
}

// Generator that exercises Bun.write() with safe temp paths
public let BunWriteGenerator = CodeGenerator("BunWriteGenerator") { b in
    let path = b.loadString("/tmp/fuzzilli-write-\(Int.random(in: 0...9999))")
    let data = b.loadString("test data \(Int.random(in: 0...9999))")
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    b.callMethod("write", on: bun, withArgs: [path, data])
}

// Generator that exercises JSON5/JSONC/JSONL parsers
public let BunJSONParserGenerator = CodeGenerator("BunJSONParserGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")

    switch Int.random(in: 0...2) {
    case 0:
        let json5 = b.getProperty("JSON5", of: bun)
        let input = b.loadString("{key: 'value', trailing: true,}")
        b.callMethod("parse", on: json5, withArgs: [input])
    case 1:
        let jsonc = b.getProperty("JSONC", of: bun)
        let input = b.loadString("{ /* comment */ \"key\": \(Int.random(in: 0...1000)) }")
        b.callMethod("parse", on: jsonc, withArgs: [input])
    default:
        let jsonl = b.getProperty("JSONL", of: bun)
        let input = b.loadString("{\"a\":\(Int.random(in: 0...100))}\n{\"b\":\(Int.random(in: 0...100))}")
        b.callMethod("parse", on: jsonl, withArgs: [input])
    }
}

// Generator that exercises Bun.connect() with localhost
public let BunConnectGenerator = CodeGenerator("BunConnectGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let hostname = b.loadString("localhost")
    let port = b.loadInt(Int64.random(in: 10000...60000))

    let openHandler = b.buildPlainFunction(with: .parameters(n: 1)) { _ in }
    let dataHandler = b.buildPlainFunction(with: .parameters(n: 2)) { _ in }
    let closeHandler = b.buildPlainFunction(with: .parameters(n: 1)) { _ in }
    let errorHandler = b.buildPlainFunction(with: .parameters(n: 2)) { _ in }

    let socket = b.createObject(with: [
        "open": openHandler,
        "data": dataHandler,
        "close": closeHandler,
        "error": errorHandler,
    ])
    let opts = b.createObject(with: [
        "hostname": hostname,
        "port": port,
        "socket": socket,
    ])
    b.callMethod("connect", on: bun, withArgs: [opts])
}

// Generator that exercises Bun.listen() on localhost with random high ports
public let BunListenGenerator = CodeGenerator("BunListenGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let hostname = b.loadString("localhost")
    let port = b.loadInt(0) // port 0 = OS assigns random port

    let openHandler = b.buildPlainFunction(with: .parameters(n: 1)) { _ in }
    let dataHandler = b.buildPlainFunction(with: .parameters(n: 2)) { _ in }
    let closeHandler = b.buildPlainFunction(with: .parameters(n: 1)) { _ in }

    let socket = b.createObject(with: [
        "open": openHandler,
        "data": dataHandler,
        "close": closeHandler,
    ])
    let opts = b.createObject(with: [
        "hostname": hostname,
        "port": port,
        "socket": socket,
    ])
    let server = b.callMethod("listen", on: bun, withArgs: [opts])
    b.callMethod("stop", on: server)
}

// Generator that exercises Bun.dns
public let BunDNSGenerator = CodeGenerator("BunDNSGenerator") { b in
    let hostnames = ["localhost", "127.0.0.1", "::1", "example.invalid", "0.0.0.0"]
    let hostname = b.loadString(hostnames.randomElement()!)
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let dns = b.getProperty("dns", of: bun)
    b.callMethod("lookup", on: dns, withArgs: [hostname])
}

// Generator that exercises Bun.sleep/sleepSync
public let BunSleepGenerator = CodeGenerator("BunSleepGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let ms = b.loadInt(Int64.random(in: 0...5))
    if Bool.random() {
        b.callMethod("sleep", on: bun, withArgs: [ms])
    } else {
        b.callMethod("sleepSync", on: bun, withArgs: [ms])
    }
}

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
private func randomColorString() -> String {
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
private func randomSafeUrl() -> String {
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
private func createRandomBody(_ b: ProgramBuilder) -> Variable {
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
        switch Int.random(in: 0...4) {
        case 0: b.callMethod("text", on: request)
        case 1: b.callMethod("json", on: request)
        case 2: b.callMethod("arrayBuffer", on: request)
        case 3: b.callMethod("blob", on: request)
        default: break
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

// Generator that exercises Bun.serve() with localhost
public let BunServeGenerator = CodeGenerator("BunServeGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")

    let handler = b.buildPlainFunction(with: .parameters(n: 1)) { args in
        let req = args[0]
        b.getProperty("url", of: req)
        b.getProperty("method", of: req)
        let body = b.loadString("OK")
        let responseConstructor = b.createNamedVariable(forBuiltin: "Response")
        b.construct(responseConstructor, withArgs: [body])
    }

    let port = b.loadInt(0)
    let opts = b.createObject(with: [
        "port": port,
        "fetch": handler,
    ])
    let server = b.callMethod("serve", on: bun, withArgs: [opts])
    b.callMethod("stop", on: server)
}

// Generator that exercises Bun.$ (shell)
public let BunShellGenerator = CodeGenerator("BunShellGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let shell = b.getProperty("$", of: bun)

    let cmds = ["echo hello", "true", "printf test", "cat /dev/null"]
    let cmd = b.loadString(cmds.randomElement()!)
    b.callMethod("text", on: b.callFunction(shell, withArgs: [cmd]))
}

// Generator that exercises Bun.markdown
public let BunMarkdownGenerator = CodeGenerator("BunMarkdownGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let markdown = b.getProperty("markdown", of: bun)

    let inputs = [
        "# Hello\\n\\nWorld",
        "| a | b |\\n|---|---|\\n| 1 | 2 |",
        "- [x] task\\n- [ ] todo",
        "```js\\nconst x = 1;\\n```",
        "~~strike~~ **bold** *italic*",
    ]
    let input = b.loadString(inputs.randomElement()!)
    b.callMethod("html", on: markdown, withArgs: [input])
}

// Generator that exercises Bun.CSRF
public let BunCSRFGenerator = CodeGenerator("BunCSRFGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let csrf = b.getProperty("CSRF", of: bun)
    let secret = b.loadString("test-secret-\(Int.random(in: 0...9999))")

    let token = b.callMethod("generate", on: csrf, withArgs: [secret])
    b.callMethod("verify", on: csrf, withArgs: [token, secret])
}

// Generator that exercises Bun.readableStreamTo* conversions
public let BunStreamConversionGenerator = CodeGenerator("BunStreamConversionGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let data = b.loadString("test data \(Int.random(in: 0...9999))")

    let blobConstructor = b.createNamedVariable(forBuiltin: "Blob")
    let blob = b.construct(blobConstructor, withArgs: [b.createArray(with: [data])])
    let stream = b.callMethod("stream", on: blob)

    switch Int.random(in: 0...5) {
    case 0: b.callMethod("readableStreamToText", on: bun, withArgs: [stream])
    case 1: b.callMethod("readableStreamToArrayBuffer", on: bun, withArgs: [stream])
    case 2: b.callMethod("readableStreamToJSON", on: bun, withArgs: [stream])
    case 3: b.callMethod("readableStreamToBlob", on: bun, withArgs: [stream])
    case 4: b.callMethod("readableStreamToArray", on: bun, withArgs: [stream])
    default: b.callMethod("readableStreamToBytes", on: bun, withArgs: [stream])
    }
}

// Generator that exercises Bun.Archive
public let BunArchiveGenerator = CodeGenerator("BunArchiveGenerator") { b in
    let archiveConstructor = b.createNamedVariable(forBuiltin: "Bun")
    let archive = b.getProperty("Archive", of: archiveConstructor)

    let data = b.loadString("not a real archive \(Int.random(in: 0...9999))")
    b.buildTryCatchFinally(tryBody: {
        b.construct(archive, withArgs: [data])
    }, catchBody: { _ in })
}

// Generator that exercises Bun.sql with safe queries on local databases
public let BunSQLGenerator = CodeGenerator("BunSQLGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let sql = b.callMethod("sql", on: bun, withArgs: [])

    let queries = [
        "SELECT 1",
        "SELECT 1 + 1 AS result",
        "SELECT CURRENT_TIMESTAMP",
    ]
    let query = b.loadString(queries.randomElement()!)
    b.buildTryCatchFinally(tryBody: {
        b.callFunction(sql, withArgs: [query])
    }, catchBody: { _ in })
}

// Generator that exercises Bun.ArrayBufferSink
public let BunArrayBufferSinkGenerator = CodeGenerator("BunArrayBufferSinkGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let sinkConstructor = b.getProperty("ArrayBufferSink", of: bun)
    let sink = b.construct(sinkConstructor)

    b.callMethod("start", on: sink)
    let data = b.loadString("chunk \(Int.random(in: 0...9999))")
    b.callMethod("write", on: sink, withArgs: [data])
    b.callMethod("end", on: sink)
}

// Generator that exercises Bun.Cookie / Bun.CookieMap
public let BunCookieGenerator = CodeGenerator("BunCookieGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")

    if Bool.random() {
        let cookieConstructor = b.getProperty("Cookie", of: bun)
        let name = b.loadString("test_cookie_\(Int.random(in: 0...999))")
        let value = b.loadString("value_\(Int.random(in: 0...999))")
        let cookie = b.construct(cookieConstructor, withArgs: [name, value])
        b.callMethod("toString", on: cookie)
    } else {
        let mapConstructor = b.getProperty("CookieMap", of: bun)
        let header = b.loadString("foo=bar; baz=qux")
        let map = b.construct(mapConstructor, withArgs: [header])
        b.callMethod("get", on: map, withArgs: [b.loadString("foo")])
        b.callMethod("has", on: map, withArgs: [b.loadString("baz")])
    }
}

// Generator that exercises Bun.dns with more methods
public let BunDNSExtendedGenerator = CodeGenerator("BunDNSExtendedGenerator") { b in
    let bun = b.createNamedVariable(forBuiltin: "Bun")
    let dns = b.getProperty("dns", of: bun)
    let hostname = b.loadString(["localhost", "127.0.0.1", "example.invalid"].randomElement()!)

    switch Int.random(in: 0...4) {
    case 0: b.callMethod("lookup", on: dns, withArgs: [hostname])
    case 1: b.callMethod("resolve", on: dns, withArgs: [hostname])
    case 2: b.callMethod("prefetch", on: dns, withArgs: [hostname])
    case 3: b.callMethod("getCacheStats", on: dns)
    default: b.callMethod("reverse", on: dns, withArgs: [b.loadString("127.0.0.1")])
    }
}

// MARK: - Bun Profile

let bunProfile = Profile(
    processArgs: { randomize in ["fuzzilli"] },
    processArgsReference: nil,

    processEnv: [
        "ASAN_OPTIONS": "allow_user_segv_handler=1:allocator_may_return_null=1:abort_on_error=1:symbolize=false:redzone=128:detect_leaks=0",
        "UBSAN_OPTIONS": "abort_on_error=1:symbolize=false:redzone=128",
        "BUN_DEBUG_QUIET_LOGS": "1",
    ],

    maxExecsBeforeRespawn: 1000,

    timeout: .value(2500),

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
        (BunSpawnGenerator,          10),
        (BunFileGenerator,           10),
        (BunWriteGenerator,           5),
        (BunJSONParserGenerator,     10),
        (BunConnectGenerator,         5),
        (BunListenGenerator,          5),
        (BunDNSGenerator,             5),
        (BunSleepGenerator,           3),
        (BunServeGenerator,          10),
        (BunShellGenerator,           5),
        (BunMarkdownGenerator,       10),
        (BunCSRFGenerator,            5),
        (BunStreamConversionGenerator, 10),
        (BunArchiveGenerator,         5),
        (BunSQLGenerator,             5),
        (BunArrayBufferSinkGenerator,  5),
        (BunCookieGenerator,          5),
        (BunDNSExtendedGenerator,     5),
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
        // new Bun.SHA256() returns an instance with .update(), .digest(), .copy()
        // Also has a static .hash() method
        "Bun.MD4"           : .constructor([] => .bunCryptoHasher),
        "Bun.MD5"           : .constructor([] => .bunCryptoHasher),
        "Bun.SHA1"          : .constructor([] => .bunCryptoHasher),
        "Bun.SHA224"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA256"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA384"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA512"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA512_256"    : .constructor([] => .bunCryptoHasher),

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

        // Compression (async)
        "Bun.zstdCompress"   : .function([.jsAnything, .opt(.object())] => .jsPromise),
        "Bun.zstdDecompress" : .function([.jsAnything] => .jsPromise),

        // Bun metadata properties
        "Bun.version"       : .string,
        "Bun.revision"      : .string,
        "Bun.enableANSIColors" : .boolean,
        "Bun.isMainThread"  : .boolean,

        // Buffer utilities
        "Bun.concatArrayBuffers" : .function([.object(), .opt(.integer), .opt(.boolean)] => .object()),
        "Bun.arrayBufferToString" : .function([.object(), .opt(.string)] => .string),
        "Bun.indexOfLine"   : .function([.object(), .opt(.integer)] => .integer),
        "Bun.allocUnsafe"   : .function([.integer] => .object()),

        // SHA function
        "Bun.sha"           : .function([.jsAnything, .opt(.string)] => .object()),

        // Memory management
        "Bun.shrink"        : .function([] => .undefined),

        // Parsers
        "Bun.TOML"          : .bunTOML,
        "Bun.YAML"          : .bunYAML,
        "Bun.JSON5"         : .bunJSON5,
        "Bun.JSONC"         : .bunJSONC,
        "Bun.JSONL"         : .bunJSONL,

        // File I/O
        "Bun.file"          : .function([.string] => .bunFile),
        "Bun.write"         : .function([.string, .jsAnything] => .jsPromise),

        // Process spawning
        "Bun.spawn"         : .function([.object()] => .bunSubprocess),
        "Bun.spawnSync"     : .function([.object()] => .bunSyncSubprocess),

        // Async sleep
        "Bun.sleep"         : .function([.number] => .jsPromise),

        // Resolve
        "Bun.resolve"       : .function([.string, .string] => .jsPromise),

        // DNS
        "Bun.dns"           : .object(withMethods: ["lookup"]),

        // Text formatting
        "Bun.wrapAnsi"      : .function([.string, .integer, .opt(.object())] => .string),

        // Server / networking
        "Bun.serve"         : .function([.object()] => .bunServer),
        "Bun.fetch"         : .function([.string, .opt(.object())] => .jsPromise),
        "Bun.build"         : .function([.object()] => .jsPromise),
        "Bun.mmap"          : .function([.string] => .object()),
        "Bun.udpSocket"     : .function([.object()] => .jsAnything),

        // SQL
        "Bun.sql"           : .function([.opt(.string)] => .jsAnything),
        "Bun.postgres"      : .function([.opt(.string)] => .jsAnything),
        "Bun.SQL"           : .function([.opt(.string)] => .jsAnything),

        // Stream conversions
        "Bun.readableStreamToArray"       : .function([.jsAnything] => .jsPromise),
        "Bun.readableStreamToArrayBuffer" : .function([.jsAnything] => .jsPromise),
        "Bun.readableStreamToText"        : .function([.jsAnything] => .jsPromise),
        "Bun.readableStreamToJSON"        : .function([.jsAnything] => .jsPromise),
        "Bun.readableStreamToBlob"        : .function([.jsAnything] => .jsPromise),
        "Bun.readableStreamToBytes"       : .function([.jsAnything] => .jsPromise),

        // Markdown
        "Bun.markdown"      : .object(withMethods: ["html", "render"]),

        // CSRF
        "Bun.CSRF"          : .object(withMethods: ["generate", "verify"]),

        // Classes
        "Bun.Archive"       : .constructor([.jsAnything, .opt(.object())] => .bunArchive),
        "Bun.ArrayBufferSink" : .constructor([] => .bunArrayBufferSink),
        "Bun.Cookie"        : .constructor([.string, .string, .opt(.object())] => .bunCookie),
        "Bun.CookieMap"     : .constructor([.opt(.string)] => .bunCookieMap),
        "Bun.Terminal"      : .constructor([.opt(.object())] => .bunTerminal),
        "Bun.S3Client"      : .constructor([.opt(.object())] => .bunS3Client),
        "Bun.RedisClient"   : .constructor([.opt(.string)] => .jsAnything),

        // Shell
        "Bun.$"             : .function([.string] => .jsPromise),

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
        bunJSON5Group,
        bunJSONCGroup,
        bunJSONLGroup,
        bunFileGroup,
        bunSubprocessGroup,
        bunSyncSubprocessGroup,
        bunFileSystemRouterGroup,
        bunArchiveGroup,
        bunServerGroup,
        bunArrayBufferSinkGroup,
        bunCookieGroup,
        bunCookieMapGroup,
    ],

    additionalEnumerations: [
        .bufferEncodingEnum,
        .hashAlgorithmEnum,
        .digestFormatEnum,
        .colorFormatEnum,
    ],

    optionalPostProcessor: nil
)
