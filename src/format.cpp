#include <napi.h>
#include "inject.h"

#include <LIEF/LIEF.hpp>
#include "LIEF/BinaryStream/SpanStream.hpp"

namespace LIEF {
namespace ELF {
    bool is_elf(BinaryStream& stream);
}

namespace PE {
    bool is_pe(BinaryStream& stream);
}

namespace MachO {
    bool is_macho(BinaryStream& stream);
}

}

Napi::Value get_executable_format(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();

    LIEF::span<const uint8_t> span(buffer.Data(), buffer.Length());
    LIEF::SpanStream stream(span);

    if (LIEF::ELF::is_elf(stream))
        return Napi::Number::New(env, kELF);
    else if (LIEF::MachO::is_macho(stream))
        return Napi::Number::New(env, kMachO);
    else if (LIEF::PE::is_pe(stream))
        return Napi::Number::New(env, kPE);

    return Napi::Number::New(env, kUnknown);
}

Napi::Value is_elf(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();

    LIEF::span<const uint8_t> span(buffer.Data(), buffer.Length());
    LIEF::SpanStream stream(span);

    bool result = LIEF::ELF::is_elf(stream);

    return Napi::Boolean::New(env, result);
}

Napi::Value is_macho(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();

    LIEF::span<const uint8_t> span(buffer.Data(), buffer.Length());
    LIEF::SpanStream stream(span);

    bool result = LIEF::MachO::is_macho(stream);

    return Napi::Boolean::New(env, result);
}

Napi::Value is_pe(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer expected").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> buffer = info[0].As<Napi::Buffer<uint8_t>>();

    LIEF::span<const uint8_t> span(buffer.Data(), buffer.Length());
    LIEF::SpanStream stream(span);

    bool result = LIEF::PE::is_pe(stream);

    return Napi::Boolean::New(env, result);
}
