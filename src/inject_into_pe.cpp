#include <napi.h>
#include "inject.h"

#include <LIEF/LIEF.hpp>
#include <locale>
#include <codecvt>

Napi::Value inject_into_pe(const Napi::CallbackInfo& info)
{
    Napi::Env env = info.Env();

    if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsString() || !info[2].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (Buffer, string, Buffer)").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> executable = info[0].As<Napi::Buffer<uint8_t>>();
    std::string resource_name = info[1].As<Napi::String>();
    Napi::Buffer<uint8_t> data = info[2].As<Napi::Buffer<uint8_t>>();
    bool gui_subsystem = false;

    if (info.Length() > 3) {
        if (!info[3].IsBoolean()) {
            Napi::TypeError::New(env, "Expected (Buffer, string, Buffer, boolean)").ThrowAsJavaScriptException();
            return env.Null();
        }

        gui_subsystem = info[3].As<Napi::Boolean>();
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("data", env.Undefined());

    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(std::vector<uint8_t>(executable.Data(), executable.Data() + executable.Length()));

    if (!binary) {
        result.Set("result", Napi::Number::New(env, InjectResult::kError));
        return result;
    }

    if (!binary->has_resources()) {
        result.Set("result", Napi::Number::New(env, InjectResult::kError));
        return result;
    }

    LIEF::PE::ResourceNode* resources = binary->resources();

    LIEF::PE::ResourceNode* rcdata_node = nullptr;
    LIEF::PE::ResourceNode* id_node = nullptr;

    auto rcdata_node_iter = std::find_if(
        std::begin(resources->childs()), std::end(resources->childs()),
        [](const LIEF::PE::ResourceNode& node) {
            return node.id() == static_cast<uint32_t>(LIEF::PE::ResourcesManager::TYPE::RCDATA);
        });

    if (rcdata_node_iter != std::end(resources->childs())) {
        rcdata_node = &*rcdata_node_iter;
    } else {
        LIEF::PE::ResourceDirectory new_rcdata_node;
        new_rcdata_node.id(static_cast<uint32_t>(LIEF::PE::ResourcesManager::TYPE::RCDATA));
        rcdata_node = &resources->add_child(new_rcdata_node);
    }

    auto id_node_iter = std::find_if(
        std::begin(rcdata_node->childs()), std::end(rcdata_node->childs()),
        [resource_name](const LIEF::PE::ResourceNode& node) {
            return node.name() == std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> {}.from_bytes(resource_name);
        });

    if (id_node_iter != std::end(rcdata_node->childs())) {
        id_node = &*id_node_iter;
    } else {
        LIEF::PE::ResourceDirectory new_id_node;
        new_id_node.name(resource_name);
        new_id_node.id(0x80000000);
        id_node = &rcdata_node->add_child(new_id_node);
    }

    if (!id_node->childs().empty()) {
        id_node->delete_child(*id_node->childs().begin());
    }

    LIEF::PE::ResourceData lang_node;
    lang_node.content(std::vector<uint8_t>(data.Data(), data.Data() + data.Length()));
    id_node->add_child(lang_node);

    binary->remove_section(".rsrc", true);

    LIEF::PE::Builder builder(*binary);
    builder.build_dos_stub(true);
    builder.build_imports(false);
    builder.build_overlay(false);
    builder.build_relocations(false);
    builder.build_resources(true);
    builder.build_tls(false);
    builder.build();

    binary = LIEF::PE::Parser::parse(builder.get_build());

    if (gui_subsystem) {
        binary->optional_header().subsystem(LIEF::PE::OptionalHeader::SUBSYSTEM::WINDOWS_GUI);
    }

    LIEF::PE::Section* section = binary->get_section(".l2");
    section->name(".rsrc");

    LIEF::PE::Builder builder2(*binary);
    builder2.build_dos_stub(true);
    builder2.build_imports(false);
    builder2.build_overlay(false);
    builder2.build_relocations(false);
    builder2.build_resources(false);
    builder2.build_tls(false);
    builder2.build();

    const std::vector<uint8_t>& output = builder2.get_build();
    Napi::Buffer<uint8_t> output_data = Napi::Buffer<uint8_t>::Copy(env, output.data(), output.size());

    result.Set("data", output_data);
    result.Set("result", Napi::Number::New(env, InjectResult::kSuccess));

    return result;
}
