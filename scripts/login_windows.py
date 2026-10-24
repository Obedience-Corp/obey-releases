"""Authenticate navigation wrappers and ordinary PowerShell console dispatch."""
import hashlib
import json
import os
from pathlib import Path
import re

from verify_candidate import command
from windows_console import quote, run_prompt


def normalized_definition(value):
    if not isinstance(value, str): raise ValueError('navigation wrapper definition is missing')
    return value.replace('\r\n', '\n').strip()


def validate_tool(data, tool, managed, foreign, reference=None):
    from login_shell import TOOLS
    expected = managed / 'bin' / (tool + ('.exe' if os.name == 'nt' else ''))
    actual = Path(data.get('native_path', ''))
    if (data.get('foreign') != [foreign] or not actual.is_absolute() or not actual.is_file()
            or not expected.is_file() or not os.path.samefile(actual, expected)):
        raise ValueError('ordinary PowerShell lost the foreign profile or resolved an unexpected external command')
    wrapped = tool in ('camp', 'fest')
    if data.get('kind') != ('Function' if wrapped else 'Application'):
        raise ValueError('ordinary PowerShell command is shadowed or missing its navigation wrapper')
    definition = normalized_definition(data.get('definition')) if wrapped else None
    if wrapped and definition != normalized_definition(reference):
        raise ValueError('PowerShell wrapper differs from the authenticated installed shell-init definition')
    version = data.get('version_output', '').strip()
    if not re.search(r'(?<![0-9.])' + re.escape(TOOLS[tool][0]) + r'(?![0-9.])', version):
        raise ValueError('ordinary PowerShell command reported an unexpected version')
    return {'path': str(actual), 'version_output': version, 'profile_sentinel_verified': True,
            'dispatch': 'function' if wrapped else 'executable', 'installed_wrapper_verified': wrapped,
            'wrapper_sha256': hashlib.sha256(definition.encode()).hexdigest() if wrapped else None}


def reference_definition(fixture, tool, managed, environment, output, stage):
    expected = managed / 'bin' / (tool + '.exe')
    # This is only the trusted reference, never the ordinary user's invocation.
    # A clean non-profile process loads exactly the verified binary's public
    # shell-init output so its normalized FunctionInfo definition can be compared.
    init = command([expected, 'shell-init', 'powershell'], environment, timeout=30)
    generated = output / f'{stage}-login-{tool}.generated.ps1'
    with generated.open('x') as stream: stream.write(init)
    script = (f"$ErrorActionPreference='Stop'; $env:PATH={quote(expected.parent)}+[IO.Path]::PathSeparator+$env:PATH; "
              f". {quote(generated)}; $command=Get-Command {quote(tool)} -ErrorAction Stop; "
              "if ($command.CommandType -ne 'Function') { throw 'installed navigation wrapper missing' }; "
              "$command.Definition | ConvertTo-Json -Compress")
    definition = command([fixture['shell'], '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], environment, json_output=True, timeout=30)
    with (output / f'{stage}-login-{tool}.reference.json').open('x') as stream:
        json.dump({'definition': definition}, stream)
    return definition


def verify_tool(fixture, tool, managed, environment, output, stage):
    from login_shell import TOOLS
    if tool not in TOOLS or not re.fullmatch(r'fa0027_keep_[0-9a-f]{12}', fixture['function']):
        raise ValueError('invalid fixed PowerShell probe')
    reference = reference_definition(fixture, tool, managed, environment, output, stage) if tool in ('camp', 'fest') else None
    args = ','.join(quote(value) for value in TOOLS[tool][1])
    body = (f"$foreign=@(& {quote(fixture['function'])}); "
            f"$effective=Get-Command {quote(tool)} -ErrorAction Stop; "
            f"$native=Get-Command {quote(tool)} -CommandType Application -ErrorAction Stop | Select-Object -First 1; "
            f"$version=(& {quote(tool)} @({args}) 2>&1 | Out-String); "
            "if ($LASTEXITCODE -ne 0) { throw 'ordinary command failed' }; "
            "$definition=if ($effective.CommandType -eq 'Function') { $effective.Definition } else { $null }; "
            "@{foreign=$foreign;kind=$effective.CommandType.ToString();native_path=$native.Source;definition=$definition;version_output=$version}")
    document = run_prompt(fixture['shell'], body, environment, output, f'{stage}-login-{tool}')
    return validate_tool(document['data'], tool, managed, fixture['value'], reference)
