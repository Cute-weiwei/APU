from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from apk_unpack.application.workflow import ToolService
from apk_unpack.config import Config
from backend.config import BackendConfig
from backend.engines import AgentEngine, EngineResult, ProviderOpenAIEngine, ToolBridge, assess_fixed_dex, task_timeout_s, _truncate_for_model
from backend.jobs import DeviceLockManager, JobManager, build_artifacts
from backend.tests.test_finalization import FakeCleanupService, llm_context, provider_config, write_run
from tests.fixtures import build_apk, build_valid_dex


class ResultRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = BackendConfig.load(data_dir=self.root / 'data')
        self.ctx = llm_context(self.root, self.config, FakeCleanupService())

    def mixed_dex(self, damaged=True):
        write_run(self.ctx.run_dir, build_valid_dex('com.example'))
        extra = build_valid_dex('org.library')
        (self.ctx.run_dir / 'dexdump/fixed/classes2.dex').write_bytes(extra[:-10] if damaged else extra)

    def run_native(self, payload):
        engine = AgentEngine(self.config)
        proc = SimpleNamespace(pid=1234, poll=lambda: 0, stdout=io.StringIO(json.dumps(payload)), stderr=io.StringIO(''), returncode=0)
        with mock.patch.object(engine, '_tail_events'), mock.patch.object(engine, '_safety_cleanup', return_value={
            'cleanup_status': 'complete', 'cleanup_incomplete': False,
        }), mock.patch('backend.engines.subprocess.Popen', return_value=proc) as spawn:
            result = engine.run(self.ctx)
        self.native_command = spawn.call_args.args[0]
        self.native_env = spawn.call_args.kwargs['env']
        return result

    def test_native_frida_override_uses_child_config_not_unsupported_cli_flag(self):
        from apk_unpack.cli import build_parser
        self.ctx.options['_frida_server_path']='/opt/frida/arm64-server'
        with mock.patch.dict(os.environ, {'APU_FRIDA_SERVER':'/opt/frida/x86-server'}):
            self.run_native({'status':'partial'})
            self.assertEqual(os.environ['APU_FRIDA_SERVER'],'/opt/frida/x86-server')
        self.assertEqual(self.native_env['APU_FRIDA_SERVER'],'/opt/frida/arm64-server')
        self.assertNotIn('--frida-server', self.native_command)
        args=build_parser().parse_args(self.native_command[3:])
        self.assertEqual(args.command,'unpack')

    def test_truncated_sibling_vetoes_success_in_all_finalizers(self):
        self.mixed_dex()
        verdict = assess_fixed_dex(self.ctx.run_dir, 'com.example')
        self.assertTrue(verdict['usable'])
        self.assertFalse(verdict['files_complete'])
        self.assertFalse(verdict['verified'])
        self.assertEqual(verdict['code'], 'truncated')
        llm = ProviderOpenAIEngine(self.config, provider_config())
        result = llm._result(self.ctx, 'model says success', None, [], {})
        self.assertEqual((result.outcome, result.error['code']), ('partial', 'truncated'))
        native = self.run_native({'status': 'partial', 'verification': {'complete': False}})
        self.assertEqual((native.outcome, native.error['code']), ('partial', 'truncated'))
        manager = object.__new__(JobManager)
        guarded = manager._guard_outcome(EngineResult('success'), self.ctx, lambda *args: None)
        self.assertEqual((guarded.outcome, guarded.error['code']), ('partial', 'truncated'))

    def test_complete_library_member_does_not_need_target_package(self):
        self.mixed_dex(damaged=False)
        verdict = assess_fixed_dex(self.ctx.run_dir, 'com.example')
        self.assertTrue(verdict['files_complete'])
        self.assertTrue(verdict['verified'])

    def test_native_partial_verdict_is_never_promoted(self):
        self.mixed_dex(damaged=False)
        result = self.run_native({'status': 'partial', 'verification': {'complete': False}})
        self.assertEqual(result.outcome, 'partial')
        self.assertEqual(result.error['code'], 'workflow_partial')

    def test_selected_inner_bypass_reaches_both_engines(self):
        self.ctx.options['inner_bypass'] = True
        bridge = ToolBridge(self.ctx)
        for name in ('prepare_android_environment', 'dump_android_dex'):
            args = {'inner_bypass':False}
            bridge._inject(name, args)
            self.assertTrue(args['inner_bypass'])
        self.run_native({'status':'partial'})
        self.assertIn('--inner-bypass', self.native_command)

    def test_native_top_level_jadx_partial_is_reported(self):
        self.mixed_dex(damaged=False)
        result = self.run_native({'status': 'decompiled', 'verification': {'complete': True},
                                  'decompilation': {'status': 'partial', 'incomplete_file_count': 7}})
        self.assertEqual((result.outcome, result.error['code']), ('partial', 'jadx_incomplete'))

    def test_jadx_time_budget_reaches_native_and_overrides_model_arguments(self):
        with mock.patch.dict(os.environ, {'APU_JADX_TIMEOUT_S':'4800'}):
            for option, expected in ((None, 4800), (0, 4800), (5400, 5400)):
                with self.subTest(option=option):
                    self.ctx.options['jadx_timeout_s'] = option
                    for name in ('verify_android_dex','decompile_android_apk'):
                        args = {'timeout_s':30}
                        ToolBridge(self.ctx)._inject(name, args)
                        self.assertEqual(args['timeout_s'], expected)
                    self.run_native({'status':'partial'})
                    position = self.native_command.index('--jadx-timeout-s')
                    self.assertEqual(self.native_command[position + 1], str(expected))

    def test_default_job_budget_reserves_jadx_but_honors_explicit_cap(self):
        self.ctx.options = {'jadx':True}
        with mock.patch.dict(os.environ, {'APU_JADX_TIMEOUT_S':'0'}):
            self.assertEqual(task_timeout_s(self.ctx), 7200)
        self.ctx.options['jadx_timeout_s'] = 9000
        self.assertEqual(task_timeout_s(self.ctx), 12600)
        self.ctx.options['timeout_s'] = 120
        self.assertEqual(task_timeout_s(self.ctx), 120)
        self.ctx.options = {'jadx':False}
        self.assertEqual(task_timeout_s(self.ctx), 3600)

    def test_large_jadx_evidence_keeps_failure_summary_for_model(self):
        quality={'status':'partial','java_file_count':44728,'incomplete_file_count':916,
                 'process_failed':True,'memory_exhausted':False,'timed_out':False,
                 'fallback':{'status':'partial','covered_file_count':915,'files':['class.java']*10000}}
        result={'run_id':self.ctx.run_id,'run_state':{'artifacts':{'decompilation':quality,
                'verification':{'complete':True,'file_count':18,'total_classes':146275,'scope':'whole_run'}}}}
        self.ctx.service.call_tool=mock.Mock(return_value=result)
        bridge=ToolBridge(self.ctx);bridge.max_chars=1000
        compact,error,text=bridge.execute('get_evidence',{})
        self.assertFalse(error)
        self.assertTrue(compact['decompilation']['process_failed'])
        self.assertEqual(compact['decompilation']['java_file_count'],44728)
        self.assertEqual(compact['verification']['file_count'],18)
        self.assertNotIn('files',compact['fallback'])
        provider=provider_config();provider.tool_result_chars=1000
        for raw in (text,json.dumps(result)):
            clipped=_truncate_for_model(raw,provider)
            self.assertLessEqual(len(clipped),1000)
            self.assertTrue(json.loads(clipped)['decompilation']['process_failed'])

    def test_verification_does_not_implicitly_repeat_jadx(self):
        self.ctx.options={'jadx':True}
        for supplied,expected in (({},False),({'run_jadx':True},True)):
            ToolBridge(self.ctx)._inject('verify_android_dex',supplied)
            self.assertEqual(supplied['run_jadx'],expected)
        self.ctx.options={'jadx':False}
        args={'run_jadx':True}
        ToolBridge(self.ctx)._inject('verify_android_dex',args)
        self.assertFalse(args['run_jadx'])

    def test_both_engines_report_timeout_separately_with_verified_dex(self):
        self.mixed_dex(damaged=False)
        quality = {'status':'partial', 'timed_out':True, 'timeout_s':12, 'java_file_count':1}
        state_file = self.ctx.run_dir / 'run.json'
        state = json.loads(state_file.read_text())
        state['artifacts']['decompilation'] = quality
        state_file.write_text(json.dumps(state))
        native = self.run_native({'status':'complete', 'verification':{'complete':True}, 'decompilation':quality})
        llm = ProviderOpenAIEngine(self.config, provider_config())._result(self.ctx, 'done', None, [], {})
        for result in (native, llm):
            self.assertEqual((result.outcome, result.error['code']), ('partial','jadx_timeout'))
            self.assertTrue(result.error['details']['timed_out'])
        self.assertTrue(assess_fixed_dex(self.ctx.run_dir, 'com.example')['verified'])

    def test_force_dump_job_overrides_model_and_cannot_finish_as_static_success(self):
        self.mixed_dex(damaged=False)
        self.ctx.options['force_dump'] = True
        args = {'force_dump':False}
        ToolBridge(self.ctx)._inject('recommend_unpack_strategy', args)
        self.assertTrue(args['force_dump'])
        result = ProviderOpenAIEngine(self.config, provider_config())._result(self.ctx, 'done', None, [], {})
        self.assertEqual((result.outcome, result.error['code']), ('partial','runtime_dump_incomplete'))
        state_file = self.ctx.run_dir/'run.json'
        state = json.loads(state_file.read_text())
        state['artifacts']['last_dump'] = {'candidates':[{'local_path':str(self.ctx.run_dir/'dexdump/fixed/classes.dex')}]}
        state_file.write_text(json.dumps(state))
        result = ProviderOpenAIEngine(self.config, provider_config())._result(self.ctx, 'done', None, [], {})
        self.assertEqual(result.outcome, 'success')

    def test_heap_exhaustion_is_distinct_from_normal_source_warnings(self):
        self.mixed_dex(damaged=False)
        quality={'status':'partial','memory_exhausted':True,'error_count':1,'returncode':1}
        state_file=self.ctx.run_dir/'run.json'
        state=json.loads(state_file.read_text())
        state['artifacts']['decompilation']=quality
        state_file.write_text(json.dumps(state))
        native=self.run_native({'status':'complete','verification':{'complete':True},'decompilation':quality})
        llm=ProviderOpenAIEngine(self.config,provider_config())._result(self.ctx,'done',None,[],{})
        for result in (native,llm):
            self.assertEqual((result.outcome,result.error['code']),('partial','jadx_memory'))
            self.assertTrue(result.error['details']['memory_exhausted'])

    def test_unexpected_jadx_exit_is_not_reported_as_normal_warnings(self):
        self.mixed_dex(damaged=False)
        quality={'status':'partial','memory_exhausted':False,'process_failed':True,
                 'java_file_count':44728,'error_count':0,'returncode':1}
        state_file=self.ctx.run_dir/'run.json';state=json.loads(state_file.read_text())
        state['artifacts']['decompilation']=quality;state_file.write_text(json.dumps(state))
        native=self.run_native({'status':'complete','verification':{'complete':True},'decompilation':quality})
        llm=ProviderOpenAIEngine(self.config,provider_config())._result(self.ctx,'done',None,[],{})
        for result in (native,llm):
            self.assertEqual((result.outcome,result.error['code']),('partial','jadx_process_error'))
            self.assertTrue(result.error['details']['process_failed'])
            self.assertEqual(result.error['details']['returncode'],1)

    def test_source_archive_keeps_fallback_separate_from_primary_java(self):
        self.mixed_dex(damaged=False)
        sources = self.ctx.run_dir/'dexdump/jadx/sources'
        sources.mkdir(parents=True)
        (sources/'Bad.java').write_text('primary source with warnings')
        fallback = self.ctx.run_dir/'dexdump/jadx/recovery/fallback-one'
        fallback.mkdir(parents=True)
        (fallback/'Bad.java').write_text('raw instructions')
        (fallback/'README.txt').write_text('Not original or compilable Java')
        state_file = self.ctx.run_dir/'run.json'
        state = json.loads(state_file.read_text())
        state['artifacts']['decompilation'] = {'status':'partial','fallback':{'output_dir':str(fallback)}}
        state_file.write_text(json.dumps(state))
        build_apk(self.ctx.upload_path, {'classes.dex':build_valid_dex('com.example')})
        result = build_artifacts(self.config,self.ctx.job_id,self.ctx.run_id,self.ctx.upload_path,self.ctx.work_dir)
        with zipfile.ZipFile(result['source_zip']) as z:
            self.assertEqual(z.read('Bad.java'), b'primary source with warnings')
            self.assertEqual(z.read('recovery/fallback/Bad.java'), b'raw instructions')
            self.assertIn('recovery/fallback/README.txt',z.namelist())

    def test_llm_reports_saved_decompilation_quality(self):
        self.mixed_dex(damaged=False)
        state_file = self.ctx.run_dir / 'run.json'
        state = json.loads(state_file.read_text())
        state['artifacts']['decompilation'] = {'status': 'partial', 'incomplete_file_count': 7}
        state_file.write_text(json.dumps(state))
        result = ProviderOpenAIEngine(self.config, provider_config())._result(self.ctx, 'done', None, [], {})
        self.assertEqual((result.outcome, result.error['code']), ('partial', 'jadx_incomplete'))

    def test_source_zip_matches_declared_quality_instead_of_larger_stale_directory(self):
        self.mixed_dex(damaged=False)
        primary=self.ctx.run_dir/'dexdump/jadx/current'
        (primary/'sources').mkdir(parents=True)
        (primary/'sources/Current.java').write_text('current')
        stale=self.ctx.run_dir/'dexdump/jadx/stale/sources';stale.mkdir(parents=True)
        for name in ('Old.java','Old2.java'):(stale/name).write_text('stale')
        state_file=self.ctx.run_dir/'run.json';state=json.loads(state_file.read_text())
        state['artifacts']['decompilation']={'status':'partial','output_dir':str(primary),'java_file_count':1}
        state_file.write_text(json.dumps(state))
        build_apk(self.ctx.upload_path,{'classes.dex':build_valid_dex('com.example')})
        result=build_artifacts(self.config,self.ctx.job_id,self.ctx.run_id,self.ctx.upload_path,self.ctx.work_dir)
        with zipfile.ZipFile(result['source_zip']) as z:
            self.assertEqual(z.read('Current.java'),b'current')
            self.assertNotIn('Old.java',z.namelist())
            self.assertEqual(json.loads(z.read('SOURCE_REPORT.json'))['decompilation']['java_file_count'],1)

    def test_source_archive_includes_business_assets_and_resources(self):
        self.mixed_dex(damaged=False)
        sources = self.ctx.run_dir / 'dexdump/jadx/sources'
        sources.mkdir(parents=True)
        (sources / 'Main.java').write_text('class Main {}')
        resources = sources.parent / 'resources'
        resources.mkdir()
        (resources / 'AndroidManifest.xml').write_text('<manifest/>')
        assets = self.ctx.run_dir / 'assets/assets/apps/__UNI__TEST/www'
        assets.mkdir(parents=True)
        (assets / 'app-service.js').write_text('business code')
        build_apk(self.ctx.upload_path, {'classes.dex': build_valid_dex('com.example')})
        result = build_artifacts(self.config, self.ctx.job_id, self.ctx.run_id, self.ctx.upload_path, self.ctx.work_dir)
        with zipfile.ZipFile(result['source_zip']) as archive:
            self.assertEqual(archive.read('assets/apps/__UNI__TEST/www/app-service.js'), b'business code')
            self.assertIn('resources/AndroidManifest.xml', archive.namelist())
            self.assertIn('Main.java', archive.namelist())
            self.assertTrue(json.loads(archive.read('SOURCE_REPORT.json'))['assets_included'])

    def test_job_finalizer_recovers_assets_when_engine_omits_extraction(self):
        self.mixed_dex(damaged=False)
        self.ctx.options['jadx'] = True
        build_apk(self.ctx.upload_path, {'classes.dex':build_valid_dex('com.example'),
                  'assets/apps/__UNI__TEST/www/app-service.js':b'business code'})
        manager = object.__new__(JobManager)
        manager.service = ToolService(Config.load(runs_dir=self.ctx.runs_dir))
        result = manager._complete_source_assets(EngineResult('success'), self.ctx, lambda *a:None)
        self.assertEqual(result.outcome, 'success')
        artifacts = build_artifacts(self.config, self.ctx.job_id, self.ctx.run_id, self.ctx.upload_path, self.ctx.work_dir)
        with zipfile.ZipFile(artifacts['source_zip']) as archive:
            self.assertEqual(archive.read('assets/apps/__UNI__TEST/www/app-service.js'), b'business code')
            self.assertTrue(json.loads(archive.read('SOURCE_REPORT.json'))['asset_extraction']['all_assets'])

    def test_incomplete_asset_extraction_downgrades_success(self):
        self.mixed_dex(damaged=False)
        self.ctx.options['jadx'] = True
        manager = object.__new__(JobManager)
        manager.service = SimpleNamespace(call_tool=lambda *a,**kw:{'extraction':{'coverage':'partial','skipped':[{'name':'large.js'}]}})
        result = manager._complete_source_assets(EngineResult('success'), self.ctx, lambda *a:None)
        self.assertEqual((result.outcome, result.error['code']), ('partial','assets_incomplete'))

    def test_custom_asset_output_is_normalized_before_packaging(self):
        self.mixed_dex(damaged=False)
        self.ctx.options['jadx'] = True
        build_apk(self.ctx.upload_path, {'assets/apps/example/www/main.js':b'business code'})
        manager = object.__new__(JobManager)
        manager.service = ToolService(Config.load(runs_dir=self.ctx.runs_dir))
        manager.service.extract_apk_assets(self.ctx.upload_path, run_id=self.ctx.run_id,
                                           output_dir=self.ctx.run_dir / 'custom-assets')
        manager._complete_source_assets(EngineResult('success'), self.ctx, lambda *a:None)
        artifacts = build_artifacts(self.config, self.ctx.job_id, self.ctx.run_id, self.ctx.upload_path, self.ctx.work_dir)
        with zipfile.ZipFile(artifacts['source_zip']) as archive:
            self.assertEqual(archive.read('assets/apps/example/www/main.js'), b'business code')

    def test_device_lease_is_retained_until_cleanup_finishes(self):
        manager = object.__new__(JobManager)
        manager.devices = DeviceLockManager()
        manager.database = SimpleNamespace(get_job=lambda job_id: {})
        next_task_entered = threading.Event()
        next_task_waiting = threading.Event()
        cleanup_entered = threading.Event()
        allow_cleanup_exit = threading.Event()
        engine = SimpleNamespace(run=lambda ctx: EngineResult('success', run_id=ctx.run_id))
        def finish(result):
            cleanup_entered.set()
            allow_cleanup_exit.wait(3)
            return result
        def competing_task():
            next_task_waiting.set()
            with manager.devices.acquire(self.ctx.serial):
                next_task_entered.set()
        first = threading.Thread(target=manager._run_engine_attempt, args=(engine, self.ctx, {'id': 'one'}), kwargs={'finish': finish})
        second = threading.Thread(target=competing_task)
        first.start()
        try:
            self.assertTrue(cleanup_entered.wait(2))
            second.start()
            self.assertTrue(next_task_waiting.wait(2))
            self.assertFalse(next_task_entered.wait(0.15), 'next task entered during cleanup')
        finally:
            allow_cleanup_exit.set()
            first.join(3)
            if second.ident is not None:
                second.join(3)
        self.assertTrue(next_task_entered.is_set())
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())

    def test_device_identity_combines_kernel_and_namespace(self):
        boot_a = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        boot_b = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        facts = {'alias-a':(boot_a,1), 'alias-b':(boot_a,1), 'other-device':(boot_b,1), 'other-container':(boot_a,2)}
        manager = object.__new__(JobManager)
        def adb(argv, **kwargs):
            boot, ns = facts[argv[1]]
            return SimpleNamespace(ok=True, stdout=boot if argv[-1].endswith('boot_id') else f'pid:[{ns}]')
        manager.service = SimpleNamespace(adb=SimpleNamespace(run=adb))
        identity = manager.device_identity('alias-a')
        self.assertEqual(identity, manager.device_identity('alias-b'))
        self.assertNotEqual(identity, manager.device_identity('other-device'))
        self.assertNotEqual(identity, manager.device_identity('other-container'))

    def test_incomplete_device_identity_keeps_serial(self):
        manager = object.__new__(JobManager)
        manager.service = SimpleNamespace(adb=SimpleNamespace(run=lambda argv, **kw:
            SimpleNamespace(ok=not argv[-1].endswith('boot_id'), stdout='pid:[1]')))
        self.assertEqual(manager.device_identity('device-a'), 'device-a')
        self.assertEqual(manager.device_identity('device-b'), 'device-b')


if __name__ == '__main__':
    unittest.main()
