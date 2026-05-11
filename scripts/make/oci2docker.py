import json, os, sys, tarfile, tempfile, io

oci_path = sys.argv[1]
out_path = sys.argv[2]
image_name = sys.argv[3]


def load_blob(tmpdir, digest):
    return os.path.join(tmpdir, 'blobs', 'sha256', digest.replace('sha256:', ''))


def resolve_manifest(tmpdir, digest):
    path = load_blob(tmpdir, digest)
    with open(path) as f:
        doc = json.load(f)

    mt = doc.get('mediaType', '')

    if 'image.manifest' in mt or 'docker.distribution.manifest' in mt:
        return doc

    # It's an index (fat manifest).  Recurse into the first non-attestation entry.
    if 'image.index' in mt:
        for entry in doc.get('manifests', []):
            emt = entry.get('mediaType', '')
            if 'attestation' in emt or entry.get('platform', {}).get('architecture') == 'unknown':
                continue
            return resolve_manifest(tmpdir, entry['digest'])

    # Docker 29 nested: top index → index → manifest.
    if 'manifests' in doc:
        for entry in doc['manifests']:
            return resolve_manifest(tmpdir, entry['digest'])

    raise ValueError(f'Cannot resolve manifest: {mt}')


with tempfile.TemporaryDirectory() as tmpdir:
    with tarfile.open(oci_path, 'r') as tf:
        tf.extractall(tmpdir)

    with open(os.path.join(tmpdir, 'index.json')) as f:
        idx = json.load(f)

    manifest = resolve_manifest(tmpdir, idx['manifests'][0]['digest'])

    config_digest = manifest['config']['digest'].replace('sha256:', '')
    config_blob = load_blob(tmpdir, manifest['config']['digest'])

    layers = []
    for layer in manifest['layers']:
        layer_digest = layer['digest'].replace('sha256:', '')
        layer_blob = load_blob(tmpdir, layer['digest'])
        layers.append((layer_digest, layer_blob))

    with tarfile.open(out_path, 'w') as out:
        ti = tarfile.TarInfo('manifest.json')
        manifest_data = json.dumps([{
            'Config': f'{config_digest}.json',
            'RepoTags': [f'{image_name}:latest'],
            'Layers': [f'{d}/layer.tar' for d, _ in layers],
        }]).encode()
        ti.size = len(manifest_data)
        out.addfile(ti, io.BytesIO(manifest_data))

        with open(config_blob, 'rb') as f:
            cfg_data = f.read()
        ti = tarfile.TarInfo(f'{config_digest}.json')
        ti.size = len(cfg_data)
        out.addfile(ti, io.BytesIO(cfg_data))

        for layer_digest, layer_blob in layers:
            ti = tarfile.TarInfo(f'{layer_digest}/')
            ti.type = tarfile.DIRTYPE
            out.addfile(ti)

            with open(layer_blob, 'rb') as f:
                layer_data = f.read()
            ti = tarfile.TarInfo(f'{layer_digest}/layer.tar')
            ti.size = len(layer_data)
            out.addfile(ti, io.BytesIO(layer_data))

        repos = {image_name: {image_name: 'latest'}}
        repos_data = json.dumps(repos).encode()
        ti = tarfile.TarInfo('repositories')
        ti.size = len(repos_data)
        out.addfile(ti, io.BytesIO(repos_data))

os.remove(oci_path)
print('Conversion done!')
