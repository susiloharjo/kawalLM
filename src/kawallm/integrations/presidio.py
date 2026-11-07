"""Microsoft Presidio recognizer wrapping the KawalLM PII detectors.

    from presidio_analyzer import AnalyzerEngine
    from kawallm.integrations.presidio import KawalLMRecognizer

    analyzer = AnalyzerEngine()
    analyzer.registry.add_recognizer(KawalLMRecognizer(supported_language="en"))
    analyzer.analyze(text, language="en")

Presidio needs an NLP model per language. If you don't have an Indonesian
spaCy model, register the recognizer under "en" (detection here is purely
deterministic, it doesn't use the NLP artifacts) or use ``analyzer_without_nlp()``.
"""

from __future__ import annotations

from presidio_analyzer import EntityRecognizer, RecognizerResult

from kawallm.pii import detect_pii

SUPPORTED_ENTITIES = [
    "ID_NIK",
    "ID_NPWP",
    "ID_PHONE",
    "ID_BANK_ACCOUNT",
    "ID_BPJS_KES",
    "ID_BPJS_TK",
    "ID_PLATE",
]

_DETECTOR_FOR = {
    "ID_BPJS_KES": "ID_BPJS",
    "ID_BPJS_TK": "ID_BPJS",
}


class KawalLMRecognizer(EntityRecognizer):
    def __init__(self, supported_language: str = "id", supported_entities: list[str] | None = None) -> None:
        super().__init__(
            supported_entities=supported_entities or SUPPORTED_ENTITIES,
            supported_language=supported_language,
            name="KawalLMRecognizer",
        )

    def load(self) -> None:  # nothing to load; data is bundled
        pass

    def analyze(self, text: str, entities: list[str], nlp_artifacts=None) -> list[RecognizerResult]:
        wanted = [e for e in (entities or self.supported_entities) if e in self.supported_entities]
        detectors = tuple(dict.fromkeys(_DETECTOR_FOR.get(e, e) for e in wanted))
        if not detectors:
            return []
        return [
            RecognizerResult(m.entity, m.start, m.end, m.score)
            for m in detect_pii(text, detectors)
            if m.entity in wanted
        ]


def analyzer_without_nlp(language: str = "id"):
    """AnalyzerEngine with only KawalLM recognizers and no spaCy model download."""
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpArtifacts, NlpEngine

    class _NoNlp(NlpEngine):
        def load(self):
            pass

        def is_loaded(self):
            return True

        def process_text(self, text, language):
            return NlpArtifacts([], [], [], [], None, language)

        def process_batch(self, texts, language, batch_size=1, n_process=1, **kwargs):
            for t in texts:
                yield t, self.process_text(t, language)

        def is_stopword(self, word, language):
            return False

        def is_punct(self, word, language):
            return False

        def get_supported_entities(self):
            return []

        def get_supported_languages(self):
            return [language]

    registry = RecognizerRegistry(supported_languages=[language])
    registry.add_recognizer(KawalLMRecognizer(supported_language=language))
    return AnalyzerEngine(registry=registry, nlp_engine=_NoNlp(), supported_languages=[language])
