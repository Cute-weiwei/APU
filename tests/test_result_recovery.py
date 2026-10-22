from __future__ import annotations

import shutil
import os
import subprocess
import threading
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from apk_unpack.domain.errors import AnalysisError
from apk_unpack.domain.jsonutil import sha256_file
from apk_unpack.config import Config
from apk_unpack.cli import build_parser, _dispatch
from apk_unpack.providers.apk import ApkInspector
from apk_unpack.providers.host import CommandResult, HostRunner, StreamResult
from apk_unpack.providers.jadx import JadxProvider
from tests.fixtures import build_apk, build_valid_dex
from tests.test_workflow import WorkflowBase, SerialAdb, inspection


class ResultRecoveryTests(unittest.TestCase):
    def test_jadx_business_counts_union_manifest_namespaces(self):
        with tempfile.TemporaryDirectory() as folder:
            out=Path(folder)/'jadx'
            for name in ['org/business/product/ui/Entry.java',
                         'org/business/product/chat/Chat.java',
                         'org/business/sdk/Library.java']:
                path=out/'sources'/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text('class Example {}')
            host=mock.Mock()
            host.run.return_value=CommandResult([],0)
            provider=JadxProvider(host,'java','jadx.jar')
            with mock.patch.object(provider,'available',return_value=True):
                report=provider.decompile([Path(folder)/'sample.dex'],out,
                    package='com.install.product',
                    target_packages=['org.business.product.ui','org.business.product'])
            self.assertEqual(report['java_file_count'],3)
            self.assertEqual(report['package_java_file_count'],2)
            self.assertIn('org.business.product',report['target_packages'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the script simulation')
    def test_shipped_scripts_on_32_and_64_bit_memory(self):
        completed = subprocess.run(
            [shutil.which('node'), str(Path(__file__).with_name('frida_script_harness.js').resolve())],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_expanded_hybrid_assets_are_extracted_without_wgt(self):
        entries = {
            'assets/apps/__UNI__TEST/www/app-service.js': b'uni business code',
            'assets/apps/__UNI__TEST/www/index.css': b'body {}',
            'assets/shopcore/www/main.js': b'hybrid business code',
            'assets/index.android.bundle': b'react native code',
        }
        apk = build_apk(self.root / 'app.apk', {'classes.dex': build_valid_dex(), **entries})
        result = ApkInspector(HostRunner()).extract_assets(apk, self.root / 'assets')
        self.assertEqual({item['name'] for item in result['files']}, set(entries))
        for name, data in entries.items():
            self.assertEqual((self.root / 'assets' / name).read_bytes(), data)

    def test_jadx_zero_exit_with_incomplete_methods_is_partial(self):
        out = self.root / 'jadx'
        sources = out / 'sources'
        sources.mkdir(parents=True)
        (sources / 'Broken.java').write_text('throw new UnsupportedOperationException("Method not decompiled: app.run()");')
        (sources / 'Good.java').write_text('class Good {}')
        host = mock.Mock()
        host.run.return_value = CommandResult([], 0)
        provider = JadxProvider(host, 'java', 'jadx.jar')
        with mock.patch.object(provider, 'available', return_value=True):
            result = provider.decompile([self.root / 'app.apk'], out)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['incomplete_file_count'], 1)
        self.assertEqual(result['java_file_count'], 2)
        self.assertFalse(result['timed_out'])
        self.assertEqual(result['completion_reason'], 'decompilation_errors')

    def test_jadx_default_and_environment_timeout_reach_process(self):
        out = self.root / 'jadx'
        out.mkdir()
        (out / 'Good.java').write_text('class Good {}')
        host = mock.Mock()
        host.run.return_value = CommandResult([], 0)
        provider = JadxProvider(host, 'java', 'jadx.jar')
        for env_value, expected in (('0', 3600), ('5400', 5400)):
            with self.subTest(env=env_value), mock.patch.dict(os.environ, {'APU_JADX_TIMEOUT_S':env_value}), mock.patch.object(provider, 'available', return_value=True):
                self.assertEqual(Config().jadx_timeout_s, expected)
                result = provider.decompile([self.root / 'app.apk'], out)
                self.assertEqual(host.run.call_args.kwargs['timeout'], expected)
                self.assertEqual(result['timeout_s'], expected)
                self.assertEqual(result['completion_reason'], 'complete')

    def test_jadx_timeout_retains_output_and_reports_real_cause(self):
        out = self.root / 'jadx'
        out.mkdir()
        (out / 'Partial.java').write_text('class Partial {}')
        for streaming in (False, True):
            with self.subTest(streaming=streaming):
                host = mock.Mock()
                host.run.return_value = CommandResult([], -1, timed_out=True, duration_s=12)
                host.stream.return_value = StreamResult([], -1, timed_out=True, duration_s=12)
                provider = JadxProvider(host, 'java', 'jadx.jar')
                with mock.patch.object(provider, 'available', return_value=True):
                    result = provider.decompile([self.root / 'app.apk'], out, timeout_s=12,
                                                cancel=threading.Event() if streaming else None)
                self.assertTrue(result['timed_out'])
                self.assertEqual((result['status'], result['completion_reason']), ('partial', 'timeout'))
                self.assertEqual(result['java_file_count'], 1)
                self.assertEqual(result['timeout_s'], 12)
                self.assertTrue((out / 'Partial.java').is_file())

    def test_jadx_default_and_override_bound_main_and_fallback_threads(self):
        out=self.root/'jadx'
        out.mkdir()
        (out/'Bad.java').write_text('/* Method not decompiled: broken */')
        host=mock.Mock()
        host.run.return_value=CommandResult([],3,stdout='ERROR - finished with errors, count: 1')
        provider=JadxProvider(host,'java','jadx.jar')
        for configured in ('1','2'):
            host.reset_mock()
            with mock.patch.dict(os.environ,{'APU_JADX_THREADS':configured}), mock.patch.object(provider,'available',return_value=True):
                q=provider.decompile([self.root/'app.apk'],out)
            self.assertEqual(q['threads'],int(configured))
            self.assertEqual(host.run.call_count,2)
            for call in host.run.call_args_list:
                argv=call.args[0]
                self.assertEqual(argv[argv.index('--threads-count')+1],configured)
        for invalid in ('0','-1','65'):
            with mock.patch.dict(os.environ,{'APU_JADX_THREADS':invalid}), self.assertRaises(ValueError):
                provider.decompile([self.root/'app.apk'],out)

    def test_jadx_timeout_without_output_is_timeout_error(self):
        host = mock.Mock()
        host.run.return_value = CommandResult([], -1, timed_out=True, duration_s=12)
        provider = JadxProvider(host, 'java', 'jadx.jar')
        with mock.patch.object(provider, 'available', return_value=True), self.assertRaises(AnalysisError) as caught:
            provider.decompile([self.root / 'app.apk'], self.root / 'jadx', timeout_s=12)
        self.assertEqual(caught.exception.code, 'timeout')
        self.assertEqual(caught.exception.details['timeout_s'], 12)
        self.assertTrue(caught.exception.details['timed_out'])

    def test_jadx_cancellation_still_cancels(self):
        host = mock.Mock()
        host.stream.return_value = StreamResult([], -1, cancelled=True)
        provider = JadxProvider(host, 'java', 'jadx.jar')
        with mock.patch.object(provider, 'available', return_value=True), self.assertRaises(AnalysisError) as caught:
            provider.decompile([self.root / 'app.apk'], self.root / 'jadx', cancel=threading.Event())
        self.assertEqual(caught.exception.code, 'cancelled')

    def test_jadx_heap_budget_reaches_main_and_fallback(self):
        large=self.root/'large.dex'
        with large.open('wb') as f:f.truncate(65*1024*1024)
        out=self.root/'jadx';out.mkdir()
        (out/'Bad.java').write_text('/* Method not decompiled: bad */')
        host=mock.Mock();host.run.return_value=CommandResult([],3)
        provider=JadxProvider(host,'java','jadx.jar')
        for configured,expected in (('0',4096),('2048',2048),('6144',6144)):
            host.reset_mock()
            with mock.patch.dict(os.environ,{'APU_JADX_HEAP_MB':configured}), mock.patch.object(provider,'available',return_value=True):
                q=provider.decompile([large],out)
            self.assertEqual(q['heap_mb'],expected)
            self.assertEqual(host.run.call_count,2)
            for call in host.run.call_args_list:
                self.assertIn('-Xmx'+str(expected)+'M',call.args[0])
                self.assertIn('-XX:+UseSerialGC',call.args[0])
                self.assertIn('-XX:NewRatio=8',call.args[0])
            self.assertEqual(q['gc_profile'],'serial')

    def test_large_input_profile_retains_all_inputs_without_inlining(self):
        large=self.root/'large.apk'
        with large.open('wb') as f:f.truncate(65*1024*1024)
        extra=self.root/'runtime.dex';extra.write_bytes(b'runtime')
        out=self.root/'jadx';out.mkdir()
        (out/'Good.java').write_text('class Good {}')
        host=mock.Mock();host.run.return_value=CommandResult([],0)
        provider=JadxProvider(host,'java','jadx.jar')
        with mock.patch.object(provider,'available',return_value=True):
            q=provider.decompile([large,extra],out)
            self.assertEqual(q['profile'],'no_inline')
            self.assertEqual(q['command'][-2:],[str(large),str(extra)])
            for flag in ('--no-inline-anonymous','--no-inline-methods','--no-inline-kotlin-lambda'):
                self.assertIn(flag,q['command'])
            small=provider.decompile([extra],out)
            self.assertEqual(small['profile'],'default')
            self.assertNotIn('--no-inline-methods',small['command'])
            self.assertEqual(small['gc_profile'],'default')
            self.assertNotIn('-XX:+UseSerialGC',small['command'])

    def test_cli_forwards_timeout_and_leaves_default_to_config(self):
        parser = build_parser()
        for command in ('verify-dex', 'decompile'):
            self.assertIsNone(parser.parse_args([command, 'run_test']).timeout)
        service = mock.Mock()
        args = parser.parse_args(['unpack', str(self.root / 'app.apk'), '--jadx-timeout-s', '5400'])
        _dispatch(service, args)
        self.assertEqual(service.unpack.call_args.kwargs['jadx_timeout_s'], 5400)

    def test_fallback_preserves_primary_and_retains_only_failed_classes(self):
        out = self.root / 'jadx'
        sources = out / 'sources/pkg'
        sources.mkdir(parents=True)
        original = 'throw new UnsupportedOperationException("Method not decompiled: broken()");'
        (sources/'Bad.java').write_text(original)
        (sources/'Good.java').write_text('class Good {}')
        def run(argv, **kwargs):
            if '--decompilation-mode' not in argv:
                return CommandResult(argv, 3, stdout='ERROR - finished with errors, count: 1', duration_s=2)
            scratch = Path(argv[argv.index('-d')+1])/'sources/pkg'
            scratch.mkdir(parents=True)
            for name in ('Bad.java','Bad$Inner.java','Good.java'):
                (scratch/name).write_text('raw bytecode instructions')
            return CommandResult(argv, 0, duration_s=1)
        host = mock.Mock()
        host.run.side_effect = run
        provider = JadxProvider(host, 'java', 'jadx.jar')
        with mock.patch.object(provider, 'available', return_value=True):
            result = provider.decompile([self.root/'app.apk'], out, timeout_s=30)
        recovery = Path(result['fallback']['output_dir'])
        self.assertEqual((sources/'Bad.java').read_text(), original)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['error_count'], 1)
        self.assertEqual(result['java_file_count'], 2)
        self.assertEqual(result['fallback']['format'], 'raw_instructions')
        self.assertEqual(result['fallback']['covered_file_count'], 1)
        self.assertTrue((recovery/'pkg/Bad.java').exists())
        self.assertTrue((recovery/'pkg/Bad$Inner.java').exists())
        self.assertFalse((recovery/'pkg/Good.java').exists())
        self.assertTrue((recovery/'README.txt').is_file())
        self.assertLessEqual(host.run.call_args.kwargs['timeout'], 30)

    def test_primary_timeout_does_not_start_another_jadx_process(self):
        out = self.root / 'jadx'
        out.mkdir()
        (out/'Bad.java').write_text('/* Method not decompiled: bad */')
        host = mock.Mock()
        host.run.return_value = CommandResult([], -1, timed_out=True)
        provider = JadxProvider(host, 'java', 'jadx.jar')
        with mock.patch.object(provider, 'available', return_value=True):
            result = provider.decompile([self.root/'app.apk'], out, timeout_s=1)
        self.assertEqual(host.run.call_count, 1)
        self.assertEqual(result['fallback']['reason'], 'timeout_budget_exhausted')

    def test_heap_failure_is_fatal_and_fallback_retains_previously_unwritten_classes(self):
        out = self.root/'jadx'
        (out/'sources').mkdir(parents=True)
        (out/'sources/Good.java').write_text('class Good {}')
        def run(argv, **kwargs):
            if '--decompilation-mode' not in argv:
                return CommandResult(argv, 1, stdout='ERROR - Process error:\njava.lang.OutOfMemoryError: Java heap space')
            scratch = Path(argv[argv.index('-d')+1])/'sources'
            scratch.mkdir()
            for name in ('Good.java','PreviouslyMissing.java'):
                (scratch/name).write_text('raw bytecode')
            return CommandResult(argv, 0)
        host = mock.Mock()
        host.run.side_effect = run
        provider = JadxProvider(host, 'java', 'jadx.jar')
        with mock.patch.object(provider, 'available', return_value=True):
            q = provider.decompile([self.root/'app.apk'],out)
        self.assertEqual((q['status'],q['completion_reason']), ('partial','memory_limit'))
        self.assertTrue(q['memory_exhausted'])
        self.assertEqual(q['primary_coverage'],'unknown_after_process_failure')
        self.assertEqual(q['fallback']['scope'],'all_classes_after_process_failure')
        self.assertEqual(q['fallback']['java_file_count'],2)
        self.assertTrue((Path(q['fallback']['output_dir'])/'PreviouslyMissing.java').is_file())


class WorkflowRecoveryTests(WorkflowBase):
    def test_initial_subset_does_not_become_whole_run_quality(self):
        one=self.run.fixed_dir/'classes.dex';one.write_bytes(build_valid_dex('com.example'))
        (self.run.fixed_dir/'classes2.dex').write_bytes(build_valid_dex('org.library'))
        with mock.patch.object(self.service.jadx,'decompile',return_value={'status':'complete'}):
            result=self.service.verify_android_dex(self.run.run_id,dex_paths=[str(one)],run_jadx=True)
        artifacts=self.run.load_run()['artifacts']
        self.assertEqual(result['verification']['scope'],'subset')
        self.assertNotIn('verification',artifacts)
        self.assertNotIn('decompilation',artifacts)
        self.assertIn('verification_jadx',artifacts)

    def test_full_repaired_set_can_replace_previous_raw_verification(self):
        (self.run.raw_dir/'classes.dex').write_bytes(build_valid_dex('com.example'))
        self.service.verify_android_dex(self.run.run_id)
        for name,package in [('classes.dex','com.example'),('classes2.dex','org.library')]:
            (self.run.fixed_dir/name).write_bytes(build_valid_dex(package))
        self.service.verify_android_dex(self.run.run_id)
        verification=self.run.load_run()['artifacts']['verification']
        self.assertEqual(verification['file_count'],2)
        self.assertEqual(verification['scope'],'whole_run')

    def test_subset_verification_cannot_replace_full_source_quality_or_dex_coverage(self):
        one=self.run.fixed_dir/'classes.dex';one.write_bytes(build_valid_dex('com.example'))
        (self.run.fixed_dir/'classes2.dex').write_bytes(build_valid_dex('org.library'))
        self.service.verify_android_dex(self.run.run_id)
        primary={'output_dir':str(self.run.jadx_dir),'status':'partial','memory_exhausted':True,'java_file_count':40000}
        self.run.update_run(artifacts={'decompilation':primary})
        with mock.patch.object(self.service.jadx,'decompile',return_value={'status':'complete','java_file_count':10}) as decompile:
            result=self.service.verify_android_dex(self.run.run_id,dex_paths=[str(one)],run_jadx=True)
            first=decompile.call_args.args[1]
            self.service.verify_android_dex(self.run.run_id,dex_paths=[str(one)],run_jadx=True)
            self.assertNotEqual(first,decompile.call_args.args[1])
        artifacts=self.run.load_run()['artifacts']
        self.assertEqual(result['verification']['file_count'],1)
        self.assertEqual(artifacts['verification']['file_count'],2)
        self.assertEqual(artifacts['verification_check']['file_count'],1)
        self.assertEqual(artifacts['decompilation'],primary)
        self.assertEqual(artifacts['verification_jadx']['java_file_count'],10)

    def test_verification_can_supply_initial_source_but_explicit_retries_use_fresh_directories(self):
        (self.run.fixed_dir/'classes.dex').write_bytes(build_valid_dex('com.example'))
        def decompile(inputs,out,**kwargs):return {'status':'complete','output_dir':str(out)}
        with mock.patch.object(self.service.jadx,'decompile',side_effect=decompile):
            self.service.verify_android_dex(self.run.run_id,run_jadx=True)
            first=self.run.load_run()['artifacts']['decompilation']['output_dir']
            self.service.decompile_android_apk(self.run.run_id,source='dex')
            second=self.run.load_run()['artifacts']['decompilation']['output_dir']
            self.service.decompile_android_apk(self.run.run_id,source='dex')
            third=self.run.load_run()['artifacts']['decompilation']['output_dir']
        self.assertEqual(len({first,second,third}),3)

    def test_identical_dex_uses_apk_resources_and_preserves_runtime_extras(self):
        original = build_valid_dex('com.example')
        library = build_valid_dex('org.library')
        apk = build_apk(self.root/'app.apk', {'classes.dex':original,'classes2.dex':library})
        observed = inspection(packed=False)
        observed['identity'] = {'path':str(apk),'sha256':sha256_file(apk),'size':apk.stat().st_size,'format':'apk'}
        self.run.update_run(target={'path':str(apk)},artifacts={'inspection':observed})
        (self.run.fixed_dir/'classes.dex').write_bytes(original)
        (self.run.fixed_dir/'classes2.dex').write_bytes(library)
        extra=self.run.fixed_dir/'classes3.dex'
        extra.write_bytes(build_valid_dex('org.runtime'))
        with mock.patch.object(self.service.jadx,'decompile',return_value={'output_dir':str(self.run.jadx_dir),'status':'complete'}) as decompile:
            result=self.service.decompile_android_apk(self.run.run_id,source='dex')
            self.assertEqual(decompile.call_args.args[0],[str(apk),extra])
            self.assertEqual(result['decompilation']['input_selection']['runtime_extra_dex_count'],1)
            self.service.verify_android_dex(self.run.run_id,run_jadx=True)
            self.assertEqual(decompile.call_args.args[0],[str(apk),extra])

    def test_apk_container_never_replaces_changed_subset_or_packed_dex(self):
        original=build_valid_dex('com.example')
        library=build_valid_dex('org.library')
        apk=build_apk(self.root/'app.apk',{'classes.dex':original,'classes2.dex':library})
        observed=inspection(packed=False)
        observed['identity']={'sha256':sha256_file(apk)}
        self.run.update_run(target={'path':str(apk)})
        one=self.run.fixed_dir/'classes.dex'
        two=self.run.fixed_dir/'classes2.dex'
        one.write_bytes(original)
        two.write_bytes(library)
        for case in ('subset','changed','packed','apk_changed'):
            with self.subTest(case=case):
                paths=[one] if case=='subset' else [one,two]
                one.write_bytes(build_valid_dex('com.runtime') if case=='changed' else original)
                observed['packing']['packed']=case=='packed'
                observed['identity']['sha256']='0'*64 if case=='apk_changed' else sha256_file(apk)
                selected, report=self.service._jadx_inputs(self.run,observed,paths)
                self.assertEqual(selected,paths)
                self.assertEqual(report['kind'],'dex')

    def test_forced_strategy_persists_for_later_recommendations(self):
        self.run.update_run(artifacts={'inspection':inspection(packed=False)})
        with mock.patch.object(self.service, '_augment_strategy_with_lessons', side_effect=lambda s,*a:s):
            first = self.service.recommend_unpack_strategy(self.run.run_id, force_dump=True)
            later = self.service.recommend_unpack_strategy(self.run.run_id)
        self.assertEqual(first['strategy']['primary'], 'frida_inmemory')
        self.assertEqual(later['strategy']['primary'], 'frida_inmemory')
        self.assertTrue(self.run.load_run()['runtime_dump_required'])

    def test_workflow_config_and_override_reach_jadx(self):
        (self.run.fixed_dir / 'classes.dex').write_bytes(build_valid_dex('com.example'))
        self.config.jadx_timeout_s = 4800
        for timeout, expected in ((None, 4800), (90, 90), (0, 4800)):
            with self.subTest(timeout=timeout), mock.patch.object(self.service.jadx, 'decompile', return_value={
                'output_dir':str(self.run.jadx_dir), 'status':'complete',
            }) as decompile:
                self.service.decompile_android_apk(self.run.run_id, source='dex', timeout_s=timeout)
                self.assertEqual(decompile.call_args.kwargs['timeout_s'], expected)
                result = self.service.verify_android_dex(self.run.run_id, run_jadx=True, timeout_s=timeout)
                self.assertEqual(decompile.call_args.kwargs['timeout_s'], expected)
                self.assertTrue(result['verification']['complete'])

    def test_workflow_persists_jadx_timeout_without_invalidating_dex(self):
        (self.run.fixed_dir / 'classes.dex').write_bytes(build_valid_dex('com.example'))
        with mock.patch.object(self.service.jadx, 'decompile', side_effect=AnalysisError('timeout','JADX timed out')):
            with self.assertRaises(AnalysisError):
                self.service.decompile_android_apk(self.run.run_id, source='dex', timeout_s=12)
        quality = self.run.load_run()['artifacts']['decompilation']
        self.assertTrue(quality['timed_out'])
        self.assertEqual(quality['timeout_s'], 12)
        self.assertTrue(self.service.verify_android_dex(self.run.run_id)['verification']['complete'])

    def test_failed_frida_preparation_still_reaches_memory_fallback(self):
        good = self.run.raw_dir / 'memory.dex'
        good.write_bytes(build_valid_dex('com.example'))
        self.service.adb = SerialAdb()
        with mock.patch.object(self.service, '_frida_reachable', return_value=False), \
             mock.patch.object(self.service, 'prepare_android_environment', side_effect=AnalysisError('frida_unavailable', 'missing server')) as prepare, \
             mock.patch.object(self.service, '_attempt_frida_cookie') as inject, \
             mock.patch.object(self.service, '_attempt_memory', return_value={'pid':42, 'candidates':[self.candidate(good)]}) as memory:
            result = self.service.dump_android_dex(self.run.run_id, serial='fake', method='auto')
        self.assertEqual(result['method'], 'memory_dd_retry')
        self.assertEqual([a['status'] for a in result['attempts']], ['failed','failed','succeeded'])
        prepare.assert_called_once()
        inject.assert_not_called()
        memory.assert_called_once()

    def test_explicit_frida_method_reports_setup_failure(self):
        self.service.adb = SerialAdb()
        with mock.patch.object(self.service, '_frida_reachable', return_value=False), \
             mock.patch.object(self.service, 'prepare_android_environment', side_effect=AnalysisError('frida_unavailable', 'missing server')), \
             mock.patch.object(self.service, '_attempt_memory') as memory:
            with self.assertRaises(AnalysisError) as error:
                self.service.dump_android_dex(self.run.run_id, serial='fake', method='frida_inmemory')
        self.assertEqual(error.exception.code, 'frida_unavailable')
        memory.assert_not_called()

    def test_unpack_prepares_install_without_frida_before_dump_fallbacks(self):
        order = []
        def prepare(*args, **kwargs):
            order.append(('prepare', kwargs))
            if kwargs.get('start_frida_server'):
                raise AnalysisError('frida_unavailable', 'missing server')
            return {}
        with mock.patch.object(self.service, 'inspect_apk', return_value={'run_id':self.run.run_id,'inspection':inspection()}), \
             mock.patch.object(self.service, 'inspect_android_device', return_value={'device':{'serial':'fake'}}), \
             mock.patch.object(self.service, 'prepare_android_environment', side_effect=prepare), \
             mock.patch.object(self.service, 'launch_android_target', side_effect=lambda *a,**kw:order.append(('launch',kw)) or {'pid':42}), \
             mock.patch.object(self.service, 'inspect_process_state', return_value={'process':{'status':{'tracer_pid':0}}}), \
             mock.patch.object(self.service, 'dump_android_dex', return_value={'method':'memory_dd','candidates':[]}) as dump, \
             mock.patch.object(self.service, 'repair_android_dex', return_value={'repair':{}}), \
             mock.patch.object(self.service, 'verify_android_dex', return_value={'verification':{'complete':True}}), \
             mock.patch.object(self.service, 'cleanup_run', return_value={'cleanup_status':'complete'}) as cleanup:
            result = self.service.unpack(str(self.root / 'app.apk'), run_id=self.run.run_id, install=True, inner_bypass=True)
        self.assertEqual(result['status'], 'success')
        self.assertEqual([item[0] for item in order], ['prepare','prepare','launch'])
        self.assertTrue(order[0][1]['allow_install'])
        self.assertFalse(order[0][1]['start_frida_server'])
        self.assertTrue(order[1][1]['inner_bypass'])
        self.assertTrue(dump.call_args.kwargs['inner_bypass'])
        cleanup.assert_called_once()

    def freeze_attempt(self, resume, process_exited=False):
        self.service.adb = mock.Mock()
        if process_exited:
            self.service.adb.shell.return_value = SimpleNamespace(ok=True, stdout='apu_process_exited')
        self.service.process = mock.Mock()
        self.service.memory = mock.Mock()
        self.service.process.signal.side_effect = [True, resume]
        self.service.process.status.return_value = {'state':'T'}
        self.service.process.wait_for_map.return_value = (SimpleNamespace(start=0x1000, size=4096), [])
        self.service.memory.rank_regions.return_value = [SimpleNamespace(start=0x1000, size=4096)]
        with mock.patch.object(self.service, '_launch_if_needed', return_value=42), \
             mock.patch.object(self.service, '_dump_region_candidates', return_value={'candidates':[{'local_path':'test.dex'}]}):
            return self.service._attempt_memory(
                self.run, 'fake', 'com.example', inspection(), pid=None, freeze=True,
                freeze_timeout_ms=500, freeze_poll_ms=1, max_region_bytes=4096,
                keep_device_files=False, cancel=None,
            )

    def test_frozen_process_confirmed_exited_does_not_mask_read_bytecode(self):
        outcome = self.freeze_attempt(False, process_exited=True)
        self.assertTrue(outcome['candidates'])
        self.assertEqual(self.run.load_mutations()[-1]['state'], 'restored')

    def test_short_lived_process_still_reaches_dump_recovery(self):
        good = self.run.raw_dir / 'spawn.dex'
        good.write_bytes(build_valid_dex('com.example'))
        self.service.adb = SerialAdb()
        for phase, code in [('launch', 'process_died'), ('inspect', 'process_not_running')]:
            with self.subTest(phase=phase), \
                 mock.patch.object(self.service, 'inspect_apk', return_value={'run_id':self.run.run_id,'inspection':inspection()}), \
                 mock.patch.object(self.service, 'inspect_android_device', return_value={'device':{'serial':'fake'}}), \
                 mock.patch.object(self.service, 'prepare_android_environment'), \
                 mock.patch.object(self.service, 'launch_android_target', side_effect=AnalysisError(code, 'process exited') if phase == 'launch' else None, return_value={'pid':42}), \
                 mock.patch.object(self.service, 'inspect_process_state', side_effect=AnalysisError(code, 'process exited') if phase == 'inspect' else None), \
                 mock.patch.object(self.service, '_frida_reachable', return_value=True), \
                 mock.patch.object(self.service, '_attempt_frida_cookie', return_value={'pid':43,'candidates':[self.candidate(good)]}) as inject, \
                 mock.patch.object(self.service, 'cleanup_run', return_value={'cleanup_status':'complete'}) as cleanup:
                result = self.service.unpack(str(self.root/'app.apk'), run_id=self.run.run_id, install=True, run_jadx=False)
            self.assertEqual(result['status'], 'success')
            self.assertTrue(result['verification']['complete'])
            self.assertEqual(result['cleanup']['cleanup_status'], 'complete')
            self.assertTrue(inject.call_args.kwargs['auto_spawn'])
            inject.assert_called_once()
            cleanup.assert_called_once()

    def test_freeze_crash_loop_reports_early_exit_not_configured_timeout(self):
        self.service.adb = mock.Mock()
        self.service.process = mock.Mock()
        self.service.process.wait_for_map.return_value = (None, [])
        self.service.process.is_alive.return_value = False
        self.service.process.wait_for_pid.side_effect = [43, 44]
        with mock.patch.object(self.service, '_launch_if_needed', return_value=42):
            with self.assertRaises(AnalysisError) as error:
                self.service._attempt_memory(
                    self.run, 'fake', 'com.example', inspection(), pid=None, freeze=True,
                    freeze_timeout_ms=120000, freeze_poll_ms=1, max_region_bytes=4096,
                    keep_device_files=False, cancel=None,
                )
        result = error.exception.projection()
        self.assertEqual(result['details']['stop_reason'], 'process_restart_limit')
        self.assertEqual(result['details']['refresh_count'], 3)
        self.assertLess(result['details']['elapsed_ms'], 120000)
        self.assertFalse(result['retryable'])
        self.assertIn('kept exiting', result['message'])
        self.assertNotIn('appeared within 120000', result['message'])
        self.service.process.signal.assert_not_called()

    def test_process_exit_does_not_establish_an_antidebug_root_cause(self):
        from apk_unpack.application.workflow import _infer_dump_root_cause
        for output in ('Process terminated', 'exited due to signal 9'):
            with self.subTest(output=output):
                cause = _infer_dump_root_cause([{'error': {'captured_output': output}}])
                self.assertIn('exit cause is unconfirmed', cause)
                self.assertNotIn('Anti-Frida/anti-debug terminated', cause)

    def test_process_inspection_permission_failure_is_not_ignored(self):
        with mock.patch.object(self.service, 'inspect_apk', return_value={'run_id':self.run.run_id,'inspection':inspection()}), \
             mock.patch.object(self.service, 'inspect_android_device', return_value={'device':{'serial':'fake'}}), \
             mock.patch.object(self.service, 'prepare_android_environment'), \
             mock.patch.object(self.service, 'launch_android_target', return_value={'pid':42}), \
             mock.patch.object(self.service, 'inspect_process_state', side_effect=AnalysisError('permission_denied', 'root unavailable')), \
             mock.patch.object(self.service, 'dump_android_dex') as dump, \
             mock.patch.object(self.service, 'cleanup_run', return_value={'cleanup_status':'complete'}) as cleanup:
            with self.assertRaises(AnalysisError) as error:
                self.service.unpack(str(self.root/'app.apk'), run_id=self.run.run_id, install=True)
        self.assertEqual(error.exception.code, 'permission_denied')
        dump.assert_not_called()
        cleanup.assert_called_once()

    def test_failed_resume_remains_retryable_and_does_not_clear_other_freezes(self):
        other = self.run.add_mutation({'kind':'kill_stop','target':'pid:99'})
        for resume in (False, RuntimeError('disconnected')):
            with self.subTest(resume=resume):
                with self.assertRaises(AnalysisError) as error:
                    self.freeze_attempt(resume)
                self.assertEqual(error.exception.code, 'cleanup_incomplete')
                mutations = self.run.load_mutations()
                self.assertEqual(mutations[-1]['state'], 'restore_failed')
                self.assertEqual(mutations[0]['mutation_id'], other['mutation_id'])
                self.assertEqual(mutations[0]['state'], 'applied')
                self.service.adb.remove.assert_called_once()

    def test_successful_resume_only_restores_its_own_mutation(self):
        self.run.add_mutation({'kind':'kill_stop','target':'pid:99'})
        self.freeze_attempt(True)
        self.assertEqual([m['state'] for m in self.run.load_mutations()], ['applied','restored'])

    def test_cleanup_failure_stops_fallback_chain(self):
        self.service.adb = SerialAdb()
        self.run.update_run(artifacts={'inspection':{**inspection(), 'packing':{'primary':'bangcle','packed':True}}})
        with mock.patch.object(self.service, '_attempt_memory', side_effect=AnalysisError('cleanup_incomplete','resume failed')) as memory:
            with self.assertRaises(AnalysisError) as error:
                self.service.dump_android_dex(self.run.run_id, serial='fake', method='auto')
        self.assertEqual(error.exception.code, 'cleanup_incomplete')
        memory.assert_called_once()

    def test_frida_setup_failure_does_not_enable_forbidden_memory_route(self):
        self.service.adb = SerialAdb()
        self.run.update_run(artifacts={'inspection':{**inspection(), 'packing':{'primary':'360','packed':True}}})
        with mock.patch.object(self.service, '_frida_reachable', return_value=False), \
             mock.patch.object(self.service, 'prepare_android_environment', side_effect=AnalysisError('frida_unavailable','missing server')), \
             mock.patch.object(self.service, '_attempt_memory') as memory:
            with self.assertRaises(AnalysisError):
                self.service.dump_android_dex(self.run.run_id, serial='fake', method='auto')
        memory.assert_not_called()

    def test_jadx_quality_from_verification_is_persisted(self):
        (self.run.fixed_dir / 'classes.dex').write_bytes(build_valid_dex('com.example'))
        partial = {'status':'partial','incomplete_file_count':2}
        with mock.patch.object(self.service.jadx, 'decompile', return_value=partial):
            result = self.service.verify_android_dex(self.run.run_id, run_jadx=True)
        self.assertTrue(result['verification']['complete'])
        self.assertEqual(self.run.load_run()['artifacts']['decompilation']['incomplete_file_count'], 2)


if __name__ == '__main__':
    unittest.main()
