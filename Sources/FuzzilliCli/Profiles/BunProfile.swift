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
        withMethods: ["match"]
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
        "match": [.string] => .boolean,
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
        "transform":  [.string] => .string,
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

// MARK: - Bun Profile

let bunProfile = Profile(
    processArgs: { randomize in ["fuzzilli"] },


    processEnv: ["ASAN_OPTIONS" : "allocator_may_return_null=1:abort_on_error=1:symbolize=false:redzone=128:detect_leaks=0", "UBSAN_OPTIONS" : "abort_on_error=1:symbolize=false:redzone=128", "BUN_DEBUG_QUIET_LOGS" : "1"],

    maxExecsBeforeRespawn: 1000,

    timeout: 2500,

    codePrefix: """
                delete globalThis.Loader;
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

    additionalCodeGenerators: [],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([]),

    disabledCodeGenerators: [],

    disabledMutators: [],

    additionalBuiltins: [
        // Bun-specific globals
        "Bun"               : .object(),
        "gc"                : .function([] => .undefined),

        // Common Node.js globals that Bun provides
        "process"           : .object(),
        "Buffer"            : .constructor([.jsAnything] => .object()),
        // Buffer.from(array | arrayBuffer | buffer | string | object, [offsetOrEncoding], [length])
        "Buffer.from"       : .function([.jsAnything, .opt(.jsAnything), .opt(.integer)] => .object()),
        // Buffer.alloc(size[, fill[, encoding]])
        "Buffer.alloc"      : .function([.integer, .opt(.jsAnything), .opt(.string)] => .object()),
        "Buffer.allocUnsafe" : .function([.integer] => .object()),
        "Buffer.allocUnsafeSlow" : .function([.integer] => .object()),
        "Buffer.isBuffer"   : .function([.jsAnything] => .boolean),
        "Buffer.isEncoding" : .function([.string] => .boolean),
        // Buffer.byteLength(string | buffer | arrayBuffer | ..., [encoding])
        "Buffer.byteLength" : .function([.jsAnything, .opt(.string)] => .integer),
        "Buffer.compare"    : .function([.object(), .object()] => .integer),
        // Buffer.concat(list[, totalLength])
        "Buffer.concat"     : .function([.object(), .opt(.integer)] => .object()),
        // Buffer.copyBytesFrom(view[, offset[, length]])
        "Buffer.copyBytesFrom" : .function([.object(), .opt(.integer), .opt(.integer)] => .object()),
        "global"            : .object(),

        // Bun constructors
        "CryptoHasher"      : .constructor([.string, .opt(.jsAnything)] => .bunCryptoHasher),
        "Transpiler"        : .constructor([.opt(.object())] => .bunTranspiler),
        "Glob"              : .constructor([.string, .opt(.object())] => .bunGlob),
        "HTMLRewriter"      : .constructor([] => .htmlRewriter),

        // Bun hash constructors (shortcuts for specific algorithms)
        "Bun.MD4"           : .constructor([] => .bunCryptoHasher),
        "Bun.MD5"           : .constructor([] => .bunCryptoHasher),
        "Bun.SHA1"          : .constructor([] => .bunCryptoHasher),
        "Bun.SHA224"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA256"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA384"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA512"        : .constructor([] => .bunCryptoHasher),
        "Bun.SHA512_256"    : .constructor([] => .bunCryptoHasher),

        // Static hash methods on hash constructors
        "Bun.MD4.hash"      : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.MD5.hash"      : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.SHA1.hash"     : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.SHA224.hash"   : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.SHA256.hash"   : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.SHA384.hash"   : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.SHA512.hash"   : .function([.jsAnything, .opt(.string)] => .jsAnything),
        "Bun.SHA512_256.hash" : .function([.jsAnything, .opt(.string)] => .jsAnything),

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
    ],

    optionalPostProcessor: nil
)
