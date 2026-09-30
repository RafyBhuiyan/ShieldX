import os, json, uuid, time

BASE = os.path.dirname(os.path.abspath(__file__))
QDIR = os.path.join(BASE, "quarantine")
INDEX = os.path.join(QDIR, "index.json")
KEY = 0x5A
os.makedirs(QDIR, exist_ok=True)

def _load():
    if os.path.exists(INDEX):
        try:
            with open(INDEX, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
    return []

def _save(items):
    try:
        with open(INDEX, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
    except OSError:
        pass

def _xor(data):
    return bytes(b ^ KEY for b in data)

def quarantine(path, threat, retries=5, delay=0.15):
    last_err = None
    abs_path = os.path.abspath(path)
    for _ in range(retries):
        try:
            with open(abs_path, "rb") as f:
                data = f.read()
            qid = uuid.uuid4().hex
            qpath = os.path.join(QDIR, qid + ".q")
            with open(qpath, "wb") as f:
                f.write(_xor(data))          # encrypted so it can't execute

            try:
                os.remove(abs_path)
            except OSError as e:
                # If removal failed, clean up the written .q file
                if os.path.exists(qpath):
                    try:
                        os.remove(qpath)
                    except OSError:
                        pass
                raise e

            items = _load()
            items.append({"id": qid, "original": abs_path, "threat": threat,
                          "time": time.strftime("%Y-%m-%d %H:%M:%S")})
            _save(items)
            return True
        except OSError as e:
            last_err = e
            time.sleep(delay)
    if last_err:
        raise last_err
    return False

def restore(qid):
    items = _load()
    matching = [i for i in items if i["id"] == qid]
    if not matching:
        return False
    item = matching[0]
    qpath = os.path.join(QDIR, qid + ".q")
    if not os.path.exists(qpath):
        return False
    with open(qpath, "rb") as f:
        data = _xor(f.read())
    target_path = item["original"]
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    with open(target_path, "wb") as f:
        f.write(data)
    delete(qid)
    return True

def delete(qid):
    p = os.path.join(QDIR, qid + ".q")
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass
    _save([i for i in _load() if i["id"] != qid])

def list_items():
    return _load()