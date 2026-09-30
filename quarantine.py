import os, json, uuid, time

BASE = os.path.dirname(os.path.abspath(__file__))
QDIR = os.path.join(BASE, "quarantine")
INDEX = os.path.join(QDIR, "index.json")
KEY = 0x5A
os.makedirs(QDIR, exist_ok=True)

def _load():
    if os.path.exists(INDEX):
        with open(INDEX) as f:
            return json.load(f)
    return []

def _save(items):
    with open(INDEX, "w") as f:
        json.dump(items, f, indent=2)

def _xor(data):
    return bytes(b ^ KEY for b in data)

def quarantine(path, threat):
    with open(path, "rb") as f:
        data = f.read()
    qid = uuid.uuid4().hex
    with open(os.path.join(QDIR, qid + ".q"), "wb") as f:
        f.write(_xor(data))          # encrypted so it can't execute
    os.remove(path)
    items = _load()
    items.append({"id": qid, "original": path, "threat": threat,
                  "time": time.strftime("%Y-%m-%d %H:%M:%S")})
    _save(items)

def restore(qid):
    item = next(i for i in _load() if i["id"] == qid)
    with open(os.path.join(QDIR, qid + ".q"), "rb") as f:
        data = _xor(f.read())
    with open(item["original"], "wb") as f:
        f.write(data)
    delete(qid)

def delete(qid):
    p = os.path.join(QDIR, qid + ".q")
    if os.path.exists(p):
        os.remove(p)
    _save([i for i in _load() if i["id"] != qid])

def list_items():
    return _load()