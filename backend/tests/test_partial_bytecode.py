import json
import tempfile
import unittest
from pathlib import Path

from backend.config import BackendConfig
from backend.engines import ProviderOpenAIEngine, assess_fixed_dex
from backend.tests.test_finalization import FakeCleanupService, llm_context, provider_config, write_run
from tests.fixtures import build_valid_dex


class PartialBytecodeTests(unittest.TestCase):
    def test_holed_business_dex_remains_partial_with_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);config=BackendConfig.load(data_dir=root/'data')
            ctx=llm_context(root,config,FakeCleanupService())
            blob=build_valid_dex('com.example',padding=8192).replace(b'\xa5'*4096,b'\0'*4096,1)
            write_run(ctx.run_dir,blob)
            verdict=assess_fixed_dex(ctx.run_dir,'com.example')
            self.assertFalse(verdict['verified'])
            self.assertTrue(verdict['recoverable'])
            result=ProviderOpenAIEngine(config,provider_config())._result(ctx,'partial business output',None,[],{})
            self.assertEqual((result.outcome,result.error['code']),('partial','partial_bytecode'))

    def test_manifest_namespace_is_shared_by_backend_and_partial_never_promotes(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=write_run(Path(tmp)/'run',build_valid_dex('org.business.ui'))
            state=json.loads((run/'run.json').read_text())
            state['artifacts']['inspection']['package']['launchable_activity']='org.business.ui.Main'
            (run/'run.json').write_text(json.dumps(state))
            self.assertTrue(assess_fixed_dex(run,'com.example')['verified'])
            state['artifacts']['last_dump']={'status':'partial','candidates':[]}
            (run/'run.json').write_text(json.dumps(state))
            verdict=assess_fixed_dex(run,'com.example')
            self.assertTrue(verdict['recoverable'])
            self.assertFalse(verdict['verified'])
            self.assertEqual(verdict['code'],'partial_bytecode')
