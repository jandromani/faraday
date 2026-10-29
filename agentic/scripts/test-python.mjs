import {spawnSync} from 'node:child_process';
import {delimiter,dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const python=process.env.FARADAY_PYTHON||(process.platform==='win32'?'python':'python3');
const pythonPath=[join(root,'python'),process.env.PYTHONPATH].filter(Boolean).join(delimiter);
const result=spawnSync(python,['-m','unittest','discover','-s','python/tests','-v'],{
  cwd:root,env:{...process.env,PYTHONPATH:pythonPath},stdio:'inherit',
});
if(result.error)console.error(`Python test runner failed: ${result.error.message}`);
process.exitCode=result.status??1;