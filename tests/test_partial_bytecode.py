from unittest import mock

from apk_unpack.application.targets import target_namespaces
from apk_unpack.application.dex_validation import assess_dex
from apk_unpack.domain.errors import AnalysisError
from tests.fixtures import build_valid_dex, build_dex
from tests.test_workflow import WorkflowBase, SerialAdb, inspection


class PartialBytecodeTests(WorkflowBase):
    def test_explicit_memory_method_retains_target_and_anonymous_companion(self):
        target = self.run.raw_dir/'target.dex'
        target.write_bytes(build_valid_dex('com.example', padding=8192).replace(b'\xa5'*4096,b'\0'*4096,1))
        library = self.run.raw_dir/'library.dex'
        library.write_bytes(build_valid_dex('org.library', padding=8192).replace(b'\xa5'*4096,b'\0'*4096,1))
        candidates = [self.candidate(p, memory_mapping='[anon:dalvik-DEX data]')
                      for p in [target,library]]
        self.service.adb = SerialAdb()
        with mock.patch.object(self.service, '_attempt_memory', return_value={'candidates':candidates}), \
             mock.patch.object(self.service, '_remember_dump_lesson') as remember:
            dump=self.service.dump_android_dex(self.run.run_id,serial='fake',method='memory_dd')
        self.assertEqual(dump['status'],'partial')
        self.assertEqual(len(dump['candidates']),2)
        self.assertEqual(dump['candidates'][1]['role'],'supporting_library')
        self.assertFalse(dump['complete'])
        remember.assert_not_called()

    def test_anonymous_companion_alone_cannot_establish_partial_target(self):
        library=self.run.raw_dir/'library.dex'
        library.write_bytes(build_valid_dex('org.library',padding=8192).replace(b'\xa5'*4096,b'\0'*4096,1))
        self.service.adb=SerialAdb()
        with mock.patch.object(self.service,'_attempt_memory',return_value={'candidates':[self.candidate(library,memory_mapping='[anon:dalvik-DEX data]')]}):
            with self.assertRaises(AnalysisError) as error:
                self.service.dump_android_dex(self.run.run_id,serial='fake',method='memory_dd')
        self.assertEqual(error.exception.code,'dump_incomplete')

    def test_rebranded_launcher_subpackage_covers_business_siblings(self):
        observed = inspection()
        observed['package']['launchable_activity'] = 'org.business.product.ui.Main'
        namespaces = target_namespaces(observed)
        self.assertEqual(namespaces, ['com.example', 'org.business.product.ui', 'org.business.product'])
        self.assertNotIn('org.business', namespaces)
        raw = self.run.raw_dir/'business.dex'
        raw.write_bytes(build_valid_dex('org.business.product.chat'))
        self.assertTrue(assess_dex(raw, 'com.example', target_packages=namespaces).recoverable)
        raw.write_bytes(build_valid_dex('org.business.sdk'))
        self.assertFalse(assess_dex(raw, 'com.example', target_packages=namespaces).recoverable)

    def test_native_workflow_decompiles_partial_dump_and_keeps_partial_status(self):
        raw=self.run.raw_dir/'app.dex';raw.write_bytes(build_valid_dex('com.example'))
        self.service.adb=SerialAdb()
        with mock.patch.object(self.service,'inspect_apk',return_value={'run_id':self.run.run_id,'inspection':inspection()}), \
             mock.patch.object(self.service,'recommend_unpack_strategy',return_value={'strategy':{'primary':'memory_dd'}}), \
             mock.patch.object(self.service,'inspect_android_device',return_value={'device':{'serial':'fake'}}), \
             mock.patch.object(self.service,'prepare_android_environment'), \
             mock.patch.object(self.service,'launch_android_target',return_value={'pid':42}), \
             mock.patch.object(self.service,'inspect_process_state',return_value={'process':{}}), \
             mock.patch.object(self.service,'dump_android_dex',return_value={'status':'partial','method':'partial_recovery','candidates':[self.candidate(raw)]}), \
             mock.patch.object(self.service.jadx,'decompile',return_value={'status':'partial','java_file_count':5,'error_count':1}) as jadx, \
             mock.patch.object(self.service,'cleanup_run',return_value={'ok':True,'cleanup_status':'complete'}) as cleanup:
            result=self.service.unpack('sample.apk',run_id=self.run.run_id,install=True)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['verification']['jadx']['java_file_count'],5)
        self.assertTrue(result['repair']['files'])
        jadx.assert_called_once()
        cleanup.assert_called_once()

    def test_manifest_launcher_can_differ_from_install_package(self):
        observed = inspection()
        observed['package']['launchable_activity'] = 'org.business.app.MainActivity'
        self.run.update_run(artifacts={'inspection': observed})
        (self.run.raw_dir/'app.dex').write_bytes(build_valid_dex('org.business.app'))
        self.service.repair_android_dex(self.run.run_id)
        result = self.service.verify_android_dex(self.run.run_id)['verification']
        self.assertTrue(result['complete'])
        self.assertIn('org.business.app', result['target_packages'])
        (self.run.fixed_dir/'classes.dex').write_bytes(build_valid_dex('org.unrelated.sdk'))
        self.assertFalse(self.service.verify_android_dex(self.run.run_id)['verification']['complete'])

    def test_manifest_loader_does_not_expand_business_coverage(self):
        for launcher in ('com.stub.StubApp', 'android.app.Activity', 'com.secneo.loader.Main'):
            self.assertEqual(target_namespaces({'package': {'name':'com.example', 'launchable_activity':launcher}}), ['com.example'])
        self.assertEqual(target_namespaces({'package': {'name':'com.example', 'launchable_activity':'.ui.Main'}}), ['com.example', 'com.example.ui'])

    def test_holes_are_recoverable_but_never_complete(self):
        raw = self.run.raw_dir/'partial.dex'
        blob = build_valid_dex('com.example', padding=8192)
        raw.write_bytes(blob.replace(b'\xa5'*4096, b'\0'*4096, 1))
        a = assess_dex(raw, 'com.example')
        self.assertTrue(a.recoverable)
        self.assertFalse(a.complete)
        self.service.adb = SerialAdb()
        with mock.patch.object(self.service, '_frida_reachable', return_value=True), \
             mock.patch.object(self.service, '_attempt_frida_cookie', side_effect=AnalysisError('process_died','exited')), \
             mock.patch.object(self.service, '_attempt_memory', side_effect=AnalysisError('process_died','exited')), \
             mock.patch.object(self.service, '_remember_dump_lesson') as remember:
            dump = self.service.dump_android_dex(self.run.run_id, serial='fake')
        self.assertEqual(dump['status'], 'partial')
        self.assertFalse(dump['complete'])
        self.assertFalse(dump['accepted_candidates'])
        self.assertEqual(len(dump['candidates']), 1)
        remember.assert_not_called()
        self.service.repair_android_dex(self.run.run_id)
        self.assertTrue(list(self.run.fixed_dir.glob('*.dex')))
        self.assertFalse(self.service.verify_android_dex(self.run.run_id)['verification']['complete'])

    def test_shell_wrong_target_and_truncation_are_not_partial_business(self):
        for name, data in [('shell',build_dex()), ('sdk',build_valid_dex('org.sdk')), ('truncated',build_valid_dex()[:-10])]:
            p=self.run.raw_dir/(name+'.dex');p.write_bytes(data)
            self.assertFalse(assess_dex(p,'com.example').recoverable)
