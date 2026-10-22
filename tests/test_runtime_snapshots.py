import hashlib
import tempfile
import unittest
from pathlib import Path

from apk_unpack.providers.dex import repair_dex_set
from tests.fixtures import build_valid_dex
from tests.test_workflow import WorkflowBase, SerialAdb
from unittest import mock


class RuntimeSnapshotTests(unittest.TestCase):
    def test_partial_live_variants_select_fewer_holes_and_preserve_raw(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);blob=build_valid_dex(padding=16384)
            bad=root/'a-worse.dex';good=root/'b-better.dex'
            offset=blob.index(b'\xa5'*4096)+4096
            bad.write_bytes(blob[:offset]+b'\0'*8192+blob[offset+8192:])
            good.write_bytes(blob[:offset]+b'\0'*4096+blob[offset+4096:])
            digests=[hashlib.sha256(p.read_bytes()).hexdigest() for p in [bad,good]]
            normal=repair_dex_set([bad,good],root/'ordinary',package='com.example')
            self.assertEqual(len(normal['files']),2)
            live=repair_dex_set([bad,good],root/'live',package='com.example',runtime_variants=True)
            self.assertEqual(len(live['files']),1)
            self.assertEqual(live['files'][0]['source_path'],str(good))
            self.assertFalse(live['complete'])
            self.assertEqual(live['duplicates'][0]['kind'],'near_runtime_variant')
            self.assertEqual(digests,[hashlib.sha256(p.read_bytes()).hexdigest() for p in [bad,good]])

    def test_distinct_class_names_are_retained_in_same_size_runtime_dex(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);paths=[]
            for package in ['com.example.one','com.example.two']:
                p=root/(package+'.dex');blob=build_valid_dex(package,padding=8192)
                offset=blob.index(b'\xa5'*4096)
                p.write_bytes(blob[:offset]+b'\0'*4096+blob[offset+4096:]);paths.append(p)
            self.assertEqual(paths[0].stat().st_size,paths[1].stat().st_size)
            result=repair_dex_set(paths,root/'fixed',runtime_variants=True)
            self.assertEqual(len(result['files']),2)

    def test_repeat_repair_removes_only_matching_outputs_from_previous_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);paths=[]
            for package in ['com.example.one','com.example.two']:
                p=root/(package+'.dex');p.write_bytes(build_valid_dex(package));paths.append(p)
            out=root/'fixed';repair_dex_set(paths,out)
            self.assertTrue((out/'classes2.dex').exists())
            other=out/'unrelated.dex';other.write_bytes(b'untouched')
            result=repair_dex_set(paths[:1],out)
            self.assertEqual(len(result['files']),1)
            self.assertFalse((out/'classes2.dex').exists())
            self.assertEqual(other.read_bytes(),b'untouched')
            self.assertEqual(len(result['removed_stale_files']),1)


class RuntimeSnapshotWorkflowTests(WorkflowBase):
    def test_live_partial_evidence_enables_snapshot_selection_in_shared_repair(self):
        blob=build_valid_dex(padding=16384);offset=blob.index(b'\xa5'*4096)+4096
        paths=[]
        for name,size in [('a-worse',8192),('b-better',4096)]:
            p=self.run.raw_dir/(name+'.dex')
            p.write_bytes(blob[:offset]+b'\0'*size+blob[offset+size:]);paths.append(p)
        self.service.adb=SerialAdb()
        with mock.patch.object(self.service,'_attempt_memory',return_value={'candidates':[self.candidate(p) for p in paths]}):
            dump=self.service.dump_android_dex(self.run.run_id,serial='fake',method='memory_dd')
        self.assertEqual(dump['status'],'partial')
        result=self.service.repair_android_dex(self.run.run_id)['repair']
        self.assertTrue(result['runtime_snapshot_selection'])
        self.assertEqual(len(result['files']),1)
        self.assertFalse(result['complete'])
