#include <napi.h>
#include "inject.h"

#include <LIEF/LIEF.hpp>

Napi::Value inject_into_elf(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 4 || !info[0].IsBuffer() || !info[1].IsString() || !info[2].IsBuffer() || !info[3].IsBoolean()) {
        Napi::TypeError::New(env, "Expected (Buffer, string, Buffer, boolean)").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> executable = info[0].As<Napi::Buffer<uint8_t>>();
    std::string note_name = info[1].As<Napi::String>();
    Napi::Buffer<uint8_t> data = info[2].As<Napi::Buffer<uint8_t>>();
    bool overwrite = info[3].As<Napi::Boolean>();

    Napi::Object result = Napi::Object::New(env);
    result.Set("data", env.Undefined());

    std::vector<uint8_t> executable_vec(executable.Data(), executable.Data() + executable.ByteLength());
    std::unique_ptr<LIEF::ELF::Binary> binary = LIEF::ELF::Parser::parse(executable_vec);

    if (!binary) {
        result.Set("result", Napi::Number::New(env, InjectResult::kError));
        return result;
    }

    LIEF::ELF::Note* existing_note = nullptr;

    for (LIEF::ELF::Note& note : binary->notes()) {
        if (note.name() == note_name) {
            existing_note = &note;
            break;
        }
    }

    if (existing_note) {
        if (!overwrite) {
            result.Set("result", Napi::Number::New(env, InjectResult::kAlreadyExists));
            return result;
        } else {
            binary->remove(*existing_note);
        }
    }

    // std::unique_ptr<LIEF::ELF::Note> note = LIEF::ELF::Note::create(note_name, LIEF::ELF::Note::TYPE::UNKNOWN,
    //     std::vector<uint8_t>(data.Data(), data.Data() + data.ByteLength()));
    // binary->add(*note);

    LIEF::ELF::Note note;
    note.name(note_name);
    note.description(std::vector<uint8_t>(data.Data(), data.Data() + data.ByteLength()));
    binary->add(note);

    std::vector<uint8_t> output = binary->raw();
    Napi::Uint8Array output_data = Napi::Uint8Array::New(env, output.size());
    std::copy(output.begin(), output.end(), output_data.Data());

    result.Set("data", output_data);
    result.Set("result", Napi::Number::New(env, InjectResult::kSuccess));

    return result;
}
