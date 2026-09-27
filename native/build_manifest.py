"""Build source-only transitional native packaging map from pinned Compose.

Run off-host. No live config/environment/data input; preserve upstream ABI and
source graph, replace Docker engine/network/control primitives explicitly.
"""
import argparse
import json
import re
from pathlib import Path
import yaml


def build(compose, pins):
    document = yaml.safe_load(compose.read_text())
    images = {row['service']: row for row in json.loads(pins.read_text())}
    services = []
    jobs = []
    for name, source in document['services'].items():
        if name not in images: raise ValueError('Unpinned service: ' + name)
        environment = source.get('environment', {})
        env_keys = sorted(environment if isinstance(environment, dict) else (row.split('=',1)[0] for row in environment))
        mounts = []
        for volume in source.get('volumes', []):
            if not isinstance(volume, str): raise ValueError('Review structured mount')
            bits = volume.split(':')
            if len(bits) < 2: raise ValueError('Review anonymous mount')
            mounts.append({'sourceTemplate': bits[0], 'destination': bits[1], 'readOnly': len(bits)>2 and bits[2]=='ro'})
        labels = source.get('labels', {})
        names = {key.split('.')[2] for key in labels if key.startswith('ofelia.job-exec.')}
        for job in sorted(names):
            prefix = 'ofelia.job-exec.'+job+'.'
            jobs.append({'name':job,'service':name,'schedule':labels[prefix+'schedule'],
                         'commandTemplate':labels[prefix+'command'], 'noOverlap':labels.get(prefix+'no-overlap','false')=='true'})
        services.append({'service':name,'unit':'mailcow-'+('mariadb' if name=='mysql-mailcow' else name.removesuffix('-mailcow'))+'.service',
                         **images[name], 'environmentKeys':env_keys, 'commandTemplate':source.get('command'),
                         'entrypointTemplate':source.get('entrypoint'), 'mounts':mounts,
                         'portTemplates':source.get('ports',[]), 'dependsOn':source.get('depends_on',[]),
                         'networkTemplates':source.get('networks',{}), 'capabilitiesToReview':source.get('cap_add',[]),
                         'privileged':source.get('privileged',False)})
    return {'phase':'transitional-native-processes-with-upstream-packaged-rootfs', 'runtimeDockerRequired':False,
            'notDeployableUntilParityGate':True,'services':services,'jobs':jobs,
            'statefulVolumes': sorted(document.get('volumes',{}))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--compose', type=Path, default=Path(__file__).resolve().parents[1]/'docker-compose.yml')
    parser.add_argument('--pins', type=Path, default=Path(__file__).with_name('pinned-images.json'))
    args=parser.parse_args()
    print(json.dumps(build(args.compose,args.pins),indent=2))
