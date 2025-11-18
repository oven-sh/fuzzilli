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

let bunProfile = Profile(
    processArgs: { randomize in ["fuzzilli"] },


    processEnv: ["ASAN_OPTIONS" : "allocator_may_return_null=1:abort_on_error=1:symbolize=false:redzone=128:detect_leaks=0", "UBSAN_OPTIONS" : "abort_on_error=1:symbolize=false:redzone=128"],

    maxExecsBeforeRespawn: 1000,

    timeout: 2100,

    codePrefix: """
                """,

    codeSuffix: """
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
        "global"            : .object(),

        // Fuzzilli integration
        "fuzzilli"          : .function([.string, .jsAnything] => .undefined),
    ],

    additionalObjectGroups: [],

    optionalPostProcessor: nil
)
