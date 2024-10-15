const fs = require("fs");
const path = require('path');

module.exports = inject = require(`./addon/${path.basename(__dirname)}.node`);
module.exports.inject = function (filename, resourceName, resourceData, options) {
    const machoSegmentName = options?.machoSegmentName || "__POSTJECT";
    const overwrite = options?.overwrite || false;
    let sentinelFuse = options?.sentinelFuse || "POSTJECT_SENTINEL_fce680ab2cc467b6e072b8b5df1996b2";

    if (!Buffer.isBuffer(resourceData)) {
        throw new TypeError("resourceData must be a buffer");
    }

    try {
        fs.accessSync(filename, fs.constants.R_OK | fs.constants.W_OK);
    } catch {
        throw new Error("Can't read and write to target executable");
    }

    let executable;

    try {
        executable = fs.readFileSync(filename);
    } catch {
        throw new Error("Couldn't read target executable");
    }
    const executableFormat = inject.get_executable_format(executable);

    if (executableFormat === inject.ExecutableFormat.kUnknown) {
        throw new Error(
            "Executable must be a supported format: ELF, PE, or Mach-O"
        );
    }

    let data;
    let result;

    switch (executableFormat) {
        case inject.ExecutableFormat.kMachO:
            {
                let sectionName = resourceName;

                // Mach-O section names are conventionally of the style __foo
                if (!sectionName.startsWith("__")) {
                    sectionName = `__${sectionName}`;
                }

                ({ result, data } = inject.inject_into_macho(
                    executable,
                    machoSegmentName,
                    sectionName,
                    resourceData,
                    overwrite
                ));

                if (result === inject.InjectResult.kAlreadyExists) {
                    throw new Error(
                        `Segment and section with that name already exists: ${machoSegmentName}/${sectionName}\n` +
                        "Use --overwrite to overwrite the existing content"
                    );
                }
            }
            break;

        case inject.ExecutableFormat.kELF:
            {
                // ELF sections usually start with a dot ("."), but this is
                // technically reserved for the system, so don't transform
                let sectionName = resourceName;

                ({ result, data } = inject.inject_into_elf(
                    executable,
                    sectionName,
                    resourceData,
                    overwrite
                ));

                if (result === inject.InjectResult.kAlreadyExists) {
                    throw new Error(
                        `Section with that name already exists: ${sectionName}` +
                        "Use --overwrite to overwrite the existing content"
                    );
                }
            }
            break;

        case inject.ExecutableFormat.kPE:
            {
                // PE resource names appear to only work if uppercase
                resourceName = resourceName.toUpperCase();

                ({ result, data } = inject.inject_into_pe(
                    executable,
                    resourceName,
                    resourceData,
                    overwrite
                ));

                if (result === inject.InjectResult.kAlreadyExists) {
                    throw new Error(
                        `Resource with that name already exists: ${resourceName}\n` +
                        "Use --overwrite to overwrite the existing content"
                    );
                }
            }
            break;
    }

    if (result !== inject.InjectResult.kSuccess) {
        throw new Error("Error when injecting resource");
    }

    const buffer = Buffer.from(data.buffer);
    const firstSentinel = buffer.indexOf(sentinelFuse);

    if (firstSentinel === -1) {
        throw new Error(
            `Could not find the sentinel ${sentinelFuse} in the binary`
        );
    }

    const lastSentinel = buffer.lastIndexOf(sentinelFuse);

    if (firstSentinel !== lastSentinel) {
        throw new Error(
            `Multiple occurences of sentinel "${sentinelFuse}" found in the binary`
        );
    }

    const colonIndex = firstSentinel + sentinelFuse.length;
    if (buffer[colonIndex] !== ":".charCodeAt(0)) {
        throw new Error(
            `Value at index ${colonIndex} must be ':' but '${buffer[
                colonIndex
            ].charCodeAt(0)}' was found`
        );
    }

    const hasResourceIndex = firstSentinel + sentinelFuse.length + 1;
    const hasResourceValue = buffer[hasResourceIndex];
    if (hasResourceValue === "0".charCodeAt(0)) {
        buffer[hasResourceIndex] = "1".charCodeAt(0);
    } else if (hasResourceValue != "1".charCodeAt(0)) {
        throw new Error(
            `Value at index ${hasResourceIndex} must be '0' or '1' but '${hasResourceValue.charCodeAt(
                0
            )}' was found`
        );
    }

    try {
        fs.writeFileSync(filename, buffer);
    } catch {
        throw new Error("Couldn't write executable");
    }
}
