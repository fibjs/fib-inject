#include <napi.h>
#include "inject.h"

Napi::Object Initialize(Napi::Env env, Napi::Object exports)
{
    Napi::Object executableFormat = Napi::Object::New(env);
    executableFormat.Set(Napi::String::New(env, "kUnknown"), Napi::Number::New(env, kUnknown));
    executableFormat.Set(Napi::String::New(env, "kELF"), Napi::Number::New(env, kELF));
    executableFormat.Set(Napi::String::New(env, "kMachO"), Napi::Number::New(env, kMachO));
    executableFormat.Set(Napi::String::New(env, "kPE"), Napi::Number::New(env, kPE));
    exports.Set(Napi::String::New(env, "ExecutableFormat"), executableFormat);

    Napi::Object injectResult = Napi::Object::New(env);
    injectResult.Set(Napi::String::New(env, "kSuccess"), Napi::Number::New(env, kSuccess));
    injectResult.Set(Napi::String::New(env, "kError"), Napi::Number::New(env, kError));
    exports.Set(Napi::String::New(env, "InjectResult"), injectResult);

    exports.Set(Napi::String::New(env, "get_executable_format"), Napi::Function::New(env, get_executable_format));

    exports.Set(Napi::String::New(env, "is_elf"), Napi::Function::New(env, is_elf));
    exports.Set(Napi::String::New(env, "is_macho"), Napi::Function::New(env, is_macho));
    exports.Set(Napi::String::New(env, "is_pe"), Napi::Function::New(env, is_pe));

    exports.Set(Napi::String::New(env, "inject_into_elf"), Napi::Function::New(env, inject_into_elf));
    exports.Set(Napi::String::New(env, "inject_into_macho"), Napi::Function::New(env, inject_into_macho));
    exports.Set(Napi::String::New(env, "inject_into_pe"), Napi::Function::New(env, inject_into_pe));

    return exports;
}

NODE_API_MODULE(addon, Initialize)
