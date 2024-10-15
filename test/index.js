const test = require('test');
test.setup();

const fs = require('fs');
const os = require('os');
const path = require('path');
const child_process = require('child_process');

const inject = require('../index');

const test_file = path.join(__dirname, "..", "bin", process.platform === 'win32' ? "\\Release\\test.exe" : "test");
const inject_file = path.join(__dirname, "inject.exe");

describe('fib-inject', () => {
    it("ExecutableFormat", () => {
        assert.deepEqual(inject.ExecutableFormat, {
            "kELF": 0,
            "kMachO": 1,
            "kPE": 2,
            "kUnknown": 3
        });
    });

    it("InjectResult", () => {
        assert.deepEqual(inject.InjectResult, {
            "kAlreadyExists": 0,
            "kError": 1,
            "kSuccess": 2
        });
    });

    describe("file format detection", () => {
        it('is_elf', () => {
            assert.equal(inject.is_elf(fs.readFile(test_file)), process.platform === 'linux');
        });

        it('is_pe', () => {
            assert.equal(inject.is_pe(fs.readFile(test_file)), process.platform === 'win32');
        });

        it('is_macho', () => {
            assert.equal(inject.is_macho(fs.readFile(test_file)), process.platform === 'darwin');
        });

        it('get_executable_format', () => {
            assert.equal(inject.get_executable_format(fs.readFile(test_file)), process.platform === 'win32' ? inject.ExecutableFormat.kPE : process.platform === 'darwin' ? inject.ExecutableFormat.kMachO : inject.ExecutableFormat.kELF);
        });
    });

    it("inject", () => {
        const res1 = child_process.execFile(test_file);
        assert.deepEqual(res1, {
            "stdout": "Hello world" + os.EOL,
            "stderr": null,
            "exitCode": 0
        });

        fs.copyFile(test_file, inject_file);
        inject.inject(inject_file, 'foobar', Buffer.from("Hello, fib-inject!"));

        if (process.platform === 'darwin')
            child_process.execFile(`codesign`, ["-s", "-", inject_file]);

        if (process.platform !== 'win32')
            fs.chmod(inject_file, 511);

        const res2 = child_process.execFile(inject_file);
        assert.deepEqual(res2, {
            "stdout": "Hello, fib-inject!" + os.EOL,
            "stderr": null,
            "exitCode": 0
        });
    });
});

test.run();
