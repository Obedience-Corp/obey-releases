"""Stable, validated version facts for ordinary command readback."""
import datetime
import json
import re
import uuid


def version_record(tool, text):
    from login_shell import TOOLS
    if tool not in TOOLS or not isinstance(text, str):
        raise ValueError('unsupported ordinary command version readback')
    text = text.strip()
    expected = TOOLS[tool][0]
    if tool != 'camp-app':
        if not re.search(r'(?<![0-9.])' + re.escape(expected) + r'(?![0-9.])', text):
            raise ValueError('ordinary command reported an unexpected version')
        return text

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate companion version field')
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=unique)
    outer = {'schemaVersion', 'requestId', 'ok', 'outcome', 'target', 'revision',
             'persistence', 'data', 'error'}
    if not isinstance(value, dict) or set(value) != outer:
        raise ValueError('companion version envelope fields differ from its schema')
    request = value['requestId']
    try:
        identifier = uuid.UUID(request) if isinstance(request, str) else None
    except ValueError as error:
        raise ValueError('invalid companion version request ID') from error
    if identifier is None or identifier.version != 7 or str(identifier) != request:
        raise ValueError('companion version requires a canonical UUIDv7 request ID')
    if (value['schemaVersion'] != 'camp.app/v1' or value['ok'] is not True
            or value['outcome'] != 'read' or value['target'] is not None
            or value['revision'] is not None or value['persistence'] != 'notApplicable'
            or value['error'] is not None):
        raise ValueError('companion version is not a successful protocol read')
    data = value['data']
    if not isinstance(data, dict) or set(data) != {
            'version', 'buildDate', 'commit', 'protocolMajor', 'protocolMinor', 'capabilities'}:
        raise ValueError('companion version/build fields differ from its contract')
    if (data['version'] != expected or type(data['protocolMajor']) is not int
            or data['protocolMajor'] != 1 or type(data['protocolMinor']) is not int
            or data['protocolMinor'] != 0 or not isinstance(data['commit'], str)
            or re.fullmatch('[0-9a-f]{40}', data['commit']) is None):
        raise ValueError('companion version/build/protocol identity is invalid')
    try:
        built = datetime.datetime.fromisoformat(data['buildDate'].replace('Z', '+00:00'))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError('companion build timestamp is invalid') from error
    if built.utcoffset() != datetime.timedelta(0):
        raise ValueError('companion build timestamp must identify UTC')
    capabilities = data['capabilities']
    if (not isinstance(capabilities, list) or not capabilities
            or any(not isinstance(item, str) or re.fullmatch('[a-z][a-z.]*', item) is None
                   for item in capabilities) or len(set(capabilities)) != len(capabilities)
            or not {'status', 'open'} <= set(capabilities)):
        raise ValueError('companion version lacks valid required capabilities')
    # Every other envelope and data field remains in the comparison. Original
    # output including this invocation's ID remains in the raw terminal record.
    return {key: item for key, item in value.items() if key != 'requestId'}
