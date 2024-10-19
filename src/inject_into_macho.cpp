#include <napi.h>
#include "inject.h"

#include <LIEF/LIEF.hpp>

Napi::Value inject_into_macho(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 4 || !info[0].IsBuffer() || !info[1].IsString() || !info[2].IsString() || !info[3].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (Buffer, string, string, Buffer, boolean)").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> executable = info[0].As<Napi::Buffer<uint8_t>>();
    std::string segment_name = info[1].As<Napi::String>();
    std::string section_name = info[2].As<Napi::String>();
    Napi::Buffer<uint8_t> data = info[3].As<Napi::Buffer<uint8_t>>();
    bool overwrite = info.Length() > 4 ? info[4].As<Napi::Boolean>() : false;

    Napi::Object result = Napi::Object::New(env);
    result.Set("data", env.Undefined());

    std::unique_ptr<LIEF::MachO::FatBinary> fat_binary = LIEF::MachO::Parser::parse(std::vector<uint8_t>(executable.Data(), executable.Data() + executable.Length()));

    if (!fat_binary) {
        result.Set("result", Napi::Number::New(env, InjectResult::kError));
        return result;
    }

    for (LIEF::MachO::Binary& binary : *fat_binary) {
        LIEF::MachO::Section* existing_section = binary.get_section(section_name);

        if (existing_section) {
            if (!overwrite) {
                result.Set("result", Napi::Number::New(env, InjectResult::kAlreadyExists));
                return result;
            }

            binary.remove_section(section_name, true);
        }

        LIEF::MachO::SegmentCommand* segment = binary.get_segment(segment_name);
        LIEF::MachO::Section section(section_name, std::vector<uint8_t>(data.Data(), data.Data() + data.Length()));

        if (!segment) {
            LIEF::MachO::SegmentCommand new_segment(segment_name);
            new_segment.max_protection(static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::READ));
            new_segment.init_protection(static_cast<uint32_t>(LIEF::MachO::SegmentCommand::VM_PROTECTIONS::READ));
            new_segment.add_section(section);
            binary.add(new_segment);
        } else {
            binary.add_section(*segment, section);
        }

        if (binary.has_code_signature()) {
            binary.remove_signature();
        }
    }

    std::vector<uint8_t> output = fat_binary->raw();
    Napi::Buffer<uint8_t> output_data = Napi::Buffer<uint8_t>::Copy(env, output.data(), output.size());

    result.Set("data", output_data);
    result.Set("result", Napi::Number::New(env, InjectResult::kSuccess));

    return result;
}