#include <napi.h>

enum ExecutableFormat {
    kELF,
    kMachO,
    kPE,
    kUnknown
};

enum InjectResult {
    kAlreadyExists,
    kError,
    kSuccess
};

// format detection declarations
Napi::Value get_executable_format(const Napi::CallbackInfo& info);

Napi::Value is_elf(const Napi::CallbackInfo& info);
Napi::Value is_macho(const Napi::CallbackInfo& info);
Napi::Value is_pe(const Napi::CallbackInfo& info);

// injection declarations
Napi::Value inject_into_elf(const Napi::CallbackInfo& info);
Napi::Value inject_into_macho(const Napi::CallbackInfo& info);
Napi::Value inject_into_pe(const Napi::CallbackInfo& info);
