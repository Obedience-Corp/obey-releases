"""Validate version identity while retaining every stable companion field."""
import copy
import json
import os
from pathlib import Path
import sys
import unittest

if os.environ.get('CANDIDATE_TEST_CONTAINER') != '1' or not Path('/.dockerenv').exists():
    raise RuntimeError('version contracts require isolated Docker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from login_version import version_record


def companion():
    return {'schemaVersion':'camp.app/v1', 'requestId':'01a16baa-065e-7cbd-8536-6f515ed73cbb',
        'ok':True,'outcome':'read','target':None,'revision':None,'persistence':'notApplicable',
        'data':{'version':'0.1.0','buildDate':'2026-10-23T10:26:30Z',
                'commit':'f33d081e0ade7f1faaa739047025a3382fe900bb','protocolMajor':1,
                'protocolMinor':0,'capabilities':['camp.open','open','operation.show','status']},'error':None}


class VersionContracts(unittest.TestCase):
    def test_only_validated_companion_request_identity_is_omitted(self):
        first=companion();second=copy.deepcopy(first)
        second['requestId']='01a16baa-065e-7cbd-8536-6f515ed73cbc'
        self.assertEqual(version_record('camp-app',json.dumps(first)),version_record('camp-app',json.dumps(second)))
        result=version_record('camp-app',json.dumps(first))
        self.assertEqual(result,{key:value for key,value in first.items() if key!='requestId'})
        self.assertNotEqual(version_record('obey','0.2.3 requestId=first'),
                            version_record('obey','0.2.3 requestId=second'))

    def test_invalid_envelopes_and_request_ids_are_not_normalized_into_success(self):
        changes=[{'ok':False},{'ok':1},{'schemaVersion':'foreign/v1'}, {'outcome':'rejected'},
                 {'target':{}},{'revision':'changed'},{'persistence':'unknown'},{'error':{}},
                 {'requestId':''},{'requestId':False}, {'requestId':'not-an-id'},
                 {'requestId':'01a16baa-065e-4cbd-8536-6f515ed73cbb'},
                 {'requestId':'01A16BAA-065E-7CBD-8536-6F515ED73CBB'}, {'extra':'unrecognized'}]
        for change in changes:
            with self.subTest(change=change):
                value=companion();value.update(change)
                with self.assertRaises(ValueError):version_record('camp-app',json.dumps(value))
        value=companion();del value['error']
        with self.assertRaises(ValueError):version_record('camp-app',json.dumps(value))

    def test_version_protocol_build_and_capabilities_must_be_valid(self):
        changes=[{'version':'9.0.0'},{'protocolMajor':True},{'protocolMajor':2},
                 {'protocolMinor':False},{'protocolMinor':1},{'commit':'unknown'},
                 {'buildDate':'not-a-date'},{'buildDate':'2026-10-23T10:26:30'},
                 {'capabilities':['open']},{'capabilities':['status','open','open']},
                 {'capabilities':['status',False]}, {'extra':'unsupported'}]
        for change in changes:
            with self.subTest(change=change):
                value=companion();value['data'].update(change)
                with self.assertRaises(ValueError):version_record('camp-app',json.dumps(value))

    def test_valid_build_and_capability_changes_remain_in_comparison(self):
        original=version_record('camp-app',json.dumps(companion()))
        for change in [{'buildDate':'2026-10-24T10:26:30Z'}, {'commit':'a'*40},
                       {'capabilities':['camp.open','open','operation.show','status','snapshot']}]:
            value=companion();value['data'].update(change)
            self.assertNotEqual(original,version_record('camp-app',json.dumps(value)))

    def test_duplicate_json_keys_noise_and_other_wrong_versions_fail(self):
        raw=json.dumps(companion()).replace('"ok": true','"ok": false, "ok": true')
        for text in [raw,'prefix '+json.dumps(companion()),'{}']:
            with self.assertRaises(ValueError):version_record('camp-app',text)
        with self.assertRaises(ValueError):version_record('obey','0.2.2')
