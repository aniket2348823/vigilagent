import traceback
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

modules = [
    'backend.core.hive',
    'backend.core.scan_lifecycle_manager',
    'backend.core.orchestrator',
    'backend.main',
]

for mod in modules:
    try:
        __import__(mod)
        print(f'{mod}: OK')
    except Exception:
        print(f'{mod}: FAILED')
        traceback.print_exc()
        sys.exit(1)

print('All imports OK')
