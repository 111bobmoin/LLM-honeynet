# example_plugin.py
# Demonstration plugin: intercept POST to /upload and return fake malware-scan result
def handle_request(method, path, headers, body, session):
    if method == "POST" and path == "/upload":
        # log and return fake result
        note = f"[{__name__}] intercepted upload {path}\n"
        with open(session["dir"] + "/module.log", "a", encoding="utf-8") as f:
            f.write(note)
        return {"handled": True, "status": 200, "headers":{"Content-Type":"application/json"}, "body": '{"result":"ok","scan":"no-threat"}'}
    return None

