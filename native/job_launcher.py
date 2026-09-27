"""Root-only timer helper for overlapping closed job templates, no API surface."""
import os
from pathlib import Path
import subprocess
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parent))
from job_policy import BY_NAME


def launch(name, runner=subprocess.run):
    if os.geteuid() != 0: raise PermissionError('Root timer operator required')
    job = BY_NAME.get(name)
    if job is None or job.no_overlap: raise ValueError('Closed overlapping job required')
    unit = job.unit.replace('@.', '@' + uuid.uuid4().hex + '.')
    runner(['/usr/bin/systemctl', 'start', '--no-block', '--', unit], check=True, timeout=15,
           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    if len(sys.argv) != 2: raise SystemExit('One closed job name required')
    launch(sys.argv[1])
