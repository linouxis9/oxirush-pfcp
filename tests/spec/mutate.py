#!/usr/bin/env python3
"""Each change of tests/spec/mutations.tsv, applied in turn to a copy of the crate: the
test `spec` must fail, in the test that the line names. It fails itself when one change
leaves the test passing.

    python3 tests/spec/mutate.py          # from the directory of the crate

The copy is in target/mutant, built in target/mutants, so that each change rebuilds the
crate alone. A change of a file of oxirush-utils, whose path begins with `oxirush-utils/`,
is applied to a copy of the oxirush-utils that the crate builds with, in
target/mutant-utils, which the copy of the crate then builds with.
"""
import json
import os
import shutil
import subprocess
import sys

ROOT = os.getcwd()
COPY = os.path.join(ROOT, 'target', 'mutant')
UTILS_COPY = os.path.join(ROOT, 'target', 'mutant-utils')
UTILS = 'oxirush-utils/'
TARGET = os.path.join(ROOT, 'target', 'mutants')


def unescape(text):
    return text.replace('\\n', '\n').replace('\\t', '\t').replace('\\\\', '\\')


def fresh_copy():
    listed = ['git', 'ls-files', '--cached', '--others', '--exclude-standard']
    files = subprocess.run(listed, cwd=ROOT, check=True, capture_output=True, text=True).stdout.split('\n')
    for name in files:
        if not name or name.startswith(('fuzz/', 'benches/')):
            continue
        source, target = os.path.join(ROOT, name), os.path.join(COPY, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(source, target)


def utils_source():
    """The directory of the oxirush-utils that the crate builds with."""
    listed = ['cargo', 'metadata', '--format-version', '1']
    metadata = json.loads(subprocess.run(listed, cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    package = next(p for p in metadata['packages'] if p['name'] == 'oxirush-utils')
    return os.path.dirname(package['manifest_path'])


def utils_copy():
    """A fresh copy of the sources of oxirush-utils, its build and its target left out."""
    shutil.rmtree(UTILS_COPY, ignore_errors=True)
    shutil.copytree(utils_source(), UTILS_COPY, ignore=shutil.ignore_patterns('target', '.git'))


def main():
    # A copy of an earlier run may have files that the crate no longer has.
    shutil.rmtree(COPY, ignore_errors=True)
    survivors = []
    lines = [line.rstrip('\n').split('\t') for line in open(os.path.join(ROOT, 'tests', 'spec', 'mutations.tsv'), encoding='utf-8')
             if line.strip() and not line.startswith('#')]
    for name, what, path, old, new, test in lines:
        old, new = unescape(old), unescape(new)
        fresh_copy()
        command = ['cargo', 'test', '--features', 'spec', '--test', 'spec']
        if path.startswith(UTILS):
            utils_copy()
            target = os.path.join(UTILS_COPY, path[len(UTILS):])
            command += ['--config', f'patch.crates-io.oxirush-utils.path="{UTILS_COPY}"']
        else:
            target = os.path.join(COPY, path)
        text = open(target, encoding='utf-8').read()
        if text.count(old) != 1:
            sys.exit(f'{name}: the text is in {path} {text.count(old)} times, and must be once')
        open(target, 'w', encoding='utf-8').write(text.replace(old, new))
        run = subprocess.run(command + ['--', '--test-threads', '1'], cwd=COPY, capture_output=True, text=True,
                             env=dict(os.environ, CARGO_TARGET_DIR=TARGET))
        output = run.stdout + run.stderr
        failed = run.returncode != 0 and f'test {test} ... FAILED' in output
        print(f'{name}: {"fails" if failed else "PASSES"} ({what})', flush=True)
        if not failed:
            survivors.append(name)
            print(output[-3000:])
        # Every copied file is fresh for the next change
        if not path.startswith(UTILS):
            shutil.copy2(os.path.join(ROOT, path), target)
    if survivors:
        sys.exit(f'the test spec passes with {", ".join(survivors)}')
    print(f'the test spec fails on each of the {len(lines)} changes')


main()
