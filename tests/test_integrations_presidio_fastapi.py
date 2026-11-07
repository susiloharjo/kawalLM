import pytest

NIK = "3171011501900001"


def test_presidio_recognizer():
    pytest.importorskip("presidio_analyzer")
    from kawallm.integrations.presidio import KawalLMRecognizer, analyzer_without_nlp

    analyzer = analyzer_without_nlp("id")
    res = analyzer.analyze(f"NIK {NIK}, kartu BPJS 0001234567890, email a@b.co.id", language="id")
    assert {r.entity_type for r in res} == {"ID_NIK", "ID_BPJS_KES", "EMAIL"}
    only = analyzer.analyze(f"NIK {NIK}, kartu BPJS 0001234567890", language="id", entities=["ID_BPJS_KES"])
    assert [r.entity_type for r in only] == ["ID_BPJS_KES"]
    rec = KawalLMRecognizer()
    rec.load()
    assert rec.analyze("x", entities=["PERSON"]) == []

    # _NoNlp methods and validate_wilayah=False
    nlp = analyzer.nlp_engine
    assert nlp.is_loaded()
    assert list(nlp.process_batch(["halo"], "id"))[0][0] == "halo"
    assert not nlp.is_stopword("dan", "id")
    assert not nlp.is_punct(".", "id")
    assert nlp.get_supported_entities() == []
    assert nlp.get_supported_languages() == ["id"]

    no_wilayah = analyzer_without_nlp("id", validate_wilayah=False)
    assert no_wilayah.analyze("NIK 9999991501900001", language="id")[0].entity_type == "ID_NIK"


def test_fastapi_middleware():
    pytest.importorskip("fastapi")
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient

    from kawallm.integrations.fastapi import KawalLMMiddleware

    events = []
    app = FastAPI()
    app.add_middleware(KawalLMMiddleware, paths=("/chat",), audit=events.append)

    @app.post("/chat")
    async def chat(req: Request):
        return await req.json()

    @app.post("/other")
    async def other(req: Request):
        return await req.json()

    c = TestClient(app)
    r = c.post(
        "/chat", json={"prompt": f"NIK {NIK}", "messages": [{"role": "user", "content": "HP 081234567890"}], "n": 1}
    )
    assert r.status_code == 200
    assert r.json() == {"prompt": "NIK <ID_NIK>", "messages": [{"role": "user", "content": "HP <ID_PHONE>"}], "n": 1}
    assert events[-1].action == "masked" and events[-1].entities == {"ID_NIK": 1, "ID_PHONE": 1}
    assert events[-1].context == {"method": "POST", "path": "/chat"}

    # Clean payload passes through without re-encoding and logs "pass"
    r_clean = c.post("/chat", json={"prompt": "halo dunia"})
    assert r_clean.status_code == 200 and r_clean.json() == {"prompt": "halo dunia"}
    assert events[-1].action == "pass"

    r = c.post("/chat", json={"prompt": "slot gacor maxwin depo pulsa"})
    assert r.status_code == 400 and "JUDOL_PINJOL" in r.json()["error"]
    assert events[-1].action == "blocked" and events[-1].categories == ["JUDOL_PINJOL"]

    assert c.post("/other", json={"prompt": f"NIK {NIK}"}).json()["prompt"] == f"NIK {NIK}"

    @app.post("/chat/raw")
    async def raw(req: Request):
        return {"len": len(await req.body())}

    assert c.post("/chat/raw", content=b"not json", headers={"content-type": "application/json"}).json() == {"len": 8}
    assert c.post("/chat/raw", content=b"plain", headers={"content-type": "text/plain"}).json() == {"len": 5}
    assert c.post("/chat", content=b"x" * 2_000_005, headers={"content-type": "application/json"}).status_code == 413
