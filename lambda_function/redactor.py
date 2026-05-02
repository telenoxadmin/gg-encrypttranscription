"""
HotelPIIRedactor
================
Presidio-based PII redactor tuned for hotel front-desk transcripts.

Detection layers (in priority order):
  1. Presidio built-in recognisers  — phones, emails, credit cards, SSN, IP, dates
  2. Hotel custom recognisers       — room numbers, partial cards, spelled-out names
  3. spaCy en_core_web_lg NER       — person names (large model = much better accuracy)
  4. names-dataset validator        — confirms spaCy PERSON tags are real names
  5. Context trigger patterns       — "last name:", "reservation for", "btw this is"
  6. Name-as-question pattern       — "Elizabeth?" in check-in context
"""

import re
import uuid
import logging
from typing import Optional

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
    EntityRecognizer,
    AnalysisExplanation,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import (
    OperatorConfig,
    RecognizerResult as AnonResult,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Words that are definitively NOT guest names in hotel transcripts
NOT_A_NAME = {
    # Filler / conjunctions
    "and","but","yet","nor","for","so","or","if","as","at","by","in",
    "of","on","to","up","do","go","hi","ok","no","yes","yep","nope",
    "yeah","nah","mhm","hey","wow","yay","huh","ugh","hmm","umm","uhh","oh","ah",
    "got","let","now","mom","dad","sir","madam","dude","bro","sis","hun","hon",
    # Titles without periods
    "dr","mr","ms","mrs","prof","rev","sir","madam",
    # Hotel brands / software
    "hilton","marriott","hyatt","hampton","expedia","kipsu","opera","folio",
    "doordash","grubhub","uber","lyft","fedex","ups","gmail","hotmail","yahoo",
    "aaa","hhonors","vip","ada","atm",
    # Room types
    "king","queen","suite","suites","double","single","standard","deluxe",
    "casita","villa","cabin",
    # US states (often capitalised mid-sentence)
    "alabama","alaska","arizona","arkansas","california","colorado","connecticut",
    "delaware","florida","georgia","hawaii","idaho","illinois","indiana","iowa",
    "kansas","kentucky","louisiana","maine","maryland","massachusetts","michigan",
    "minnesota","mississippi","missouri","montana","nebraska","nevada","oregon",
    "ohio","oklahoma","pennsylvania","rhode","tennessee","texas","utah","vermont",
    "virginia","washington","wisconsin","wyoming","hampshire","jersey","mexico",
    "york","carolina","dakota","richmond","alexandria",
    # Days / months
    "monday","tuesday","wednesday","thursday","friday","saturday","sunday",
    "january","february","march","april","may","june","july","august",
    "september","october","november","december",
    # Common words that score as names in DB but aren't
    "frozen","enroll","upsell","howdy","anywho","waltz","kawaii","mooji",
    "wiki","art","sue","kip","park","nah","clark","clark","dude","lame",
    "sing","take","coke","baby","some","rune","duke","farm","long","black",
    "white","spring","holiday","heck","just","still","house","make","same",
    "amen","diamond","apple","fish","lord","visa","triple","double","single",
    # Hotel / hospitality terms
    "hotel","room","lobby","desk","check","card","cash","bill","tax","rate",
    "stay","floor","building","parking","entrance","exit","elevator","stairs",
    "breakfast","lunch","dinner","brunch","buffet","restaurant","kitchen","menu",
    "pool","bar","spa","gym","tavern","grille","bistro","lounge","cafe","grill",
    "reservation","confirmation","availability","upgrade","booking","checkin",
    # Greetings / fillers
    "welcome","hello","thanks","sorry","please","enjoy","help","bye","perfect",
    "fantastic","wonderful","excellent","absolutely","definitely","really","great",
    "good","okay","fine","sure","right","well","real","true","next","new",
}

# Words that appear as "Name?" questions but are NOT guest names
NOT_NAME_QUESTION = {
    "Hello","Pardon","Sorry","Okay","Right","Correct","Really","Seriously",
    "Key","Keys","Door","Hilton","Honors","Hampton","Suite","Suites","King",
    "Queen","Park","Parking","Frozen","Dude","Wiki","Gmail","Enroll","Upsell",
    "Anywho","Kawaii","Howdy","Nah","DoorDash","GrubHub","Uber","Lyft","FedEx",
    "Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday",
    "January","February","March","April","June","July","August","September",
    "October","November","December","Virginia","Construction","Printer",
    "Hilton","Hotmail","Yahoo","Philly","Triple","Double","Single","What",
    "When","Where","Which","Who","How","Why","Yeah","Nope","Nah","Sure",
    "Clark","Tavern","Grille","Mooji","Monarches","Cyanard","Dendu",
}

# Hotel check-in context words for name-as-question validation
CHECKIN_CONTEXT = re.compile(
    r"check(?:ing)?[\s\-]in|reservation|digital\s+key|physical\s+key|"
    r"\bkeys?\b|checking\s+out|honor|room|stay|tonight|welcome|"
    r"hallway|floor|elevator|door|parking|front\s+desk|lobby|check\s+out",
    re.IGNORECASE
)

# ─────────────────────────────────────────────────────────────────────────────
#  CUSTOM RECOGNISERS
# ─────────────────────────────────────────────────────────────────────────────

def make_room_recogniser() -> PatternRecognizer:
    """Detects room numbers: 'room 224', 'Room no 452', 'Suite 3B'."""
    return PatternRecognizer(
        supported_entity="ROOM_NUMBER",
        patterns=[
            Pattern(
                "room_with_keyword",
                r"\b(?:room\s+(?:no\.?|number|num\.?|#)?\s*|suite\s+|rm\.?\s+)([0-9][A-Z0-9]{0,5})\b",
                0.85,
            ),
        ],
        context=["room", "suite", "unit", "cabin", "villa"],
    )


def make_partial_card_recogniser() -> PatternRecognizer:
    """Detects 'last 4 of credit card 7756', 'card ending in 1234'."""
    return PatternRecognizer(
        supported_entity="CREDIT_CARD_PARTIAL",
        patterns=[
            Pattern(
                "last_4_digits",
                r"\b(?:last\s+(?:4|four)\s+(?:digits?\s+)?(?:of\s+)?(?:credit\s+card|card)?|"
                r"card\s+ending\s+in|ending\s+in)\s*\d{4}\b",
                0.9,
            ),
        ],
    )


def make_spelled_name_recogniser() -> PatternRecognizer:
    """Detects spelled-out names: K-I-M-M-E-Y, R-E-E-D (min 5 letters)."""
    return PatternRecognizer(
        supported_entity="PERSON",
        patterns=[
            Pattern(
                "spelled_out_name",
                r"\b(?:[A-Z][\s\-]){4,}[A-Z]\b",
                0.9,
            ),
        ],
    )


def make_phone_recogniser() -> PatternRecognizer:
    """
    Tighter phone pattern — requires separator between groups
    to avoid matching 7-digit fragments like '25812769'.
    """
    return PatternRecognizer(
        supported_entity="PHONE_NUMBER",
        patterns=[
            Pattern(
                "us_phone_with_separators",
                r"\b(?:\+?1[-.\s]?)?\(?(\d{3})\)?[-.\s]\d{3}[-.\s]\d{4}\b",
                0.85,
            ),
            Pattern(
                "phone_after_keyword",
                r"\b(?:phone|cell|mobile|contact)[\s:]*(?:number[\s:]*)?"
                r"(\d{3}[-.\s]\d{3}[-.\s]\d{4})\b",
                0.9,
            ),
            Pattern(
                "partial_phone_last4",
                r"\b(?:phone\s+number\s+ending\s+in\s+\d{4})\b",
                0.8,
            ),
        ],
        context=["phone", "call", "contact", "number", "cell", "mobile"],
    )


# ─────────────────────────────────────────────────────────────────────────────
#  NAMES-DATASET VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────

class NamesDatasetValidator:
    """
    Validates whether a token is likely a person name using names-dataset.
    Used to filter false positives from spaCy NER.
    """

    def __init__(self):
        try:
            from names_dataset import NameDataset
            logger.info("Loading names-dataset...")
            self._nd = NameDataset()
            logger.info("names-dataset loaded.")
        except ImportError:
            logger.warning("names-dataset not installed — name validation disabled.")
            self._nd = None

    def is_name(self, word: str) -> bool:
        """Return True if word is likely a person name."""
        if not self._nd:
            return True  # trust spaCy if DB unavailable
        if word.lower() in NOT_A_NAME or len(word) < 2:
            return False
        try:
            result = self._nd.search(word)
        except Exception:
            return True
        if not result:
            # Not in DB — accept if title-case alpha (rare foreign name)
            return word[0].isupper() and word.replace("-","").replace("'","").isalpha()

        fn = result.get("first_name") or {}
        ln = result.get("last_name") or {}
        fn_ranks = [v for v in (fn.get("rank") or {}).values() if v and v > 0]
        ln_ranks = [v for v in (ln.get("rank") or {}).values() if v and v > 0]

        if fn_ranks and min(fn_ranks) < 5000:
            return True
        if ln_ranks and min(ln_ranks) < 3000:
            return True
        return False

    def is_name_phrase(self, phrase: str) -> bool:
        """Return True if all words in the phrase are likely names."""
        words = re.split(r"[\s\-]", phrase.strip())
        return all(self.is_name(w) for w in words if w)


# ─────────────────────────────────────────────────────────────────────────────
#  CONTEXT TRIGGER PATTERNS  (hotel-specific name detection)
# ─────────────────────────────────────────────────────────────────────────────

NAME_TRIGGER = re.compile(
    r"(?:"
    r"last\s+name(?:\s+(?:is|on\s+the\s+reservation))?"
    r"|first\s+name\??"
    r"|reservation\s+(?:for|under)"
    r"|checked?\s+in(?:\s+(?:as|under|for))?"
    r"|checking\s+in(?:\s+(?:as|under|for))?"
    r"|under\s+(?:the\s+name\s+)?"
    r"|name(?:\s+is)?(?:\s+on\s+(?:your\s+)?(?:the\s+)?reservation)?"
    r"|my\s+name\s+is"
    r"|what(?:'?s)?\s+(?:the\s+)?(?:last\s+)?name"
    r"|have\s+a\s+reservation\s+for"
    r"|i\s+have\s+you\s+(?:here\s+)?(?:as\s+|checking\s+in\s+)?"
    r"|i(?:'ve)?\s+got\s+you\s+(?:here\s+)?(?:as\s+|checking\s+in\s+)?"
    r"|thank\s+you[\s,]+(?:so\s+much[\s,]+)?(?:mr\.?|ms\.?|mrs\.?)?\s*(?!for\s+)"
    r"|mr\.\s*|ms\.\s*|mrs\.\s*|miss\s+|dr\.\s+"
    r"|btw\s+this\s+is\s*"
    r"|this\s+is\s+(?!the\s|a\s|our\s|your\s|his\s|her\s|my\s|that\s|it\s|"
    r"why\s|how\s|what\s|where\s|when\s|because\s|going\s|just\s|really\s|"
    r"actually\s|basically\s|also\s|still\s|kind\s|sort\s)"
    r"|at\s+the\s+moment\s+"
    r"|guest(?:\s+name)?(?:\s+is)?\s+"
    r"|welcome\s+(?:back\s+)?(?:mr\.?|ms\.?|mrs\.?|miss|dr\.?)?\s*"
    r"|didn'?t\s+catch\s+(?:your\s+)?name\??\s*"
    r"|are\s+you\s+(?:the\s+)?"
    r")",
    re.IGNORECASE,
)

NAME_PATTERN = re.compile(
    r"(?:"
    r"(?:[A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{0,25}\s+)?"
    r"(?:van\s+(?:der?\s+)?|de\s+(?:la\s+|los?\s+|las?\s+)?|du\s+|le\s+|la\s+"
    r"|bin\s+|binte\s+|al-?|el-?|o'|mc|mac)"
    r"[A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{1,25}"
    r"(?:\s+[A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{1,25})*"
    r"|"
    r"[A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{1,25}"
    r"(?:[-\s][A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{1,25}){0,2}"
    r")"
)

SPELLED_NAME   = re.compile(r"\b(?:[A-Z][\s\-]){4,}[A-Z]\b")
ROOM_CONTEXT   = re.compile(
    r"(?:you(?:'re|\s+are)\s+in\s+|in\s+room\s+|lobby\s+room\s+|"
    r"room\s+(?:number\s+)?(?:is\s+)?|suite\s+|unit\s+)"
    r"([0-9]{2,4}[A-Z]?)\b",
    re.IGNORECASE,
)
STANDALONE_NAME = re.compile(
    r"^\s*(?:[\w\-]+:\s*)?([A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{2,25}"
    r"(?:\s+[A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{2,25}){0,2})\s*$",
    re.MULTILINE,
)
NAME_QUESTION_PAT = re.compile(
    r"(?<![A-Za-z])([A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{2,25}"
    r"(?:\s+[A-Z\u00C0-\u024F][a-zA-Z\u00C0-\u024F'\-]{1,25}){0,1})\?"
)

FILLER_PREFIXES = re.compile(
    r"^(?:hey|hi|hello|alrighty|alright|okay|ok|so|well|now|and|but|"
    r"great|perfect|awesome|sure|right|wow|oh|ah|uh|um|hmm|anywho|"
    r"howdy|dude|bro|guys?)\s+",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
#  TOKEN STORE
# ─────────────────────────────────────────────────────────────────────────────

class TokenStore:
    def __init__(self):
        self._fwd: dict = {}
        self._rev: dict = {}

    def get_or_create(self, entity_type: str, value: str) -> str:
        key = f"{entity_type}::{value}"
        if key in self._fwd:
            return self._fwd[key]
        token = f"[{entity_type}_{uuid.uuid4().hex[:8].upper()}]"
        self._fwd[key] = token
        self._rev[token] = {"type": entity_type, "original": value}
        return token

    def to_dict(self) -> dict:
        return {"token_to_original": self._rev}

    def reset(self):
        self._fwd.clear()
        self._rev.clear()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN REDACTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class HotelPIIRedactor:
    """
    Presidio-based PII redactor for hotel transcripts.

    Args:
        mode: "redact" — replace with [REDACTED_TYPE]
              "tokenize" — replace with stable reversible token
        confidence_threshold: Presidio confidence cutoff (0-1), default 0.6
        spacy_model: spaCy model name, default "en_core_web_lg"
    """

    def __init__(
        self,
        mode: str = "redact",
        confidence_threshold: float = 0.6,
        spacy_model: str = "en_core_web_lg",
    ):
        self.mode      = mode
        self.threshold = confidence_threshold
        self._stats: dict = {}

        # Initialise names validator
        self._validator = NamesDatasetValidator()

        # Initialise Presidio
        self._analyzer  = self._build_analyzer(spacy_model)
        self._anonymizer = AnonymizerEngine()

        # Token store (per-document, reset each call)
        self._token_store = TokenStore()

    # ── Builder ──────────────────────────────────────────────────────────────

    def _build_analyzer(self, spacy_model: str) -> AnalyzerEngine:
        """Build AnalyzerEngine with spaCy NLP + all custom recognisers."""
        cfg = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": spacy_model}],
        }
        provider = NlpEngineProvider(nlp_configuration=cfg)
        nlp_engine = provider.create_engine()

        engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

        # Add custom recognisers
        engine.registry.add_recognizer(make_room_recogniser())
        engine.registry.add_recognizer(make_partial_card_recogniser())
        engine.registry.add_recognizer(make_spelled_name_recogniser())
        engine.registry.add_recognizer(make_phone_recogniser())

        return engine

    # ── Main entry point ──────────────────────────────────────────────────────

    def process(self, text: str) -> tuple[str, Optional[dict]]:
        """
        Redact or tokenize PII in text.

        Returns:
            (processed_text, token_map_dict_or_None)
        """
        self._stats = {}
        self._token_store.reset()

        # ── Step 1: Presidio analysis ─────────────────────────────────────────
        results = self._analyzer.analyze(
            text=text,
            language="en",
            entities=[
                "PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD",
                "CREDIT_CARD_PARTIAL", "US_SSN", "IP_ADDRESS", "DATE_TIME",
                "ROOM_NUMBER", "LOCATION",
            ],
            score_threshold=self.threshold,
        )

        # ── Step 2: Validate PERSON entities with names-dataset ───────────────
        validated = []
        for r in results:
            if r.entity_type == "PERSON":
                span = text[r.start:r.end].strip()
                # Strip filler prefixes
                span = FILLER_PREFIXES.sub("", span).strip()
                if not span or span.lower() in NOT_A_NAME:
                    continue
                # Reject if contains digits (timestamp artifacts)
                if any(c.isdigit() for c in span):
                    continue
                # Validate with names-dataset
                words = re.split(r"[\s\-]", span)
                words = [w for w in words if w and len(w) > 1]
                if not words:
                    continue
                if not self._validator.is_name_phrase(span):
                    continue
                validated.append(r)
            else:
                validated.append(r)

        # ── Step 3: Add spans from context trigger patterns ───────────────────
        extra_spans = self._find_context_spans(text)
        # Convert to RecognizerResult format
        for start, end, entity_type in extra_spans:
            validated.append(
                RecognizerResult(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    score=0.85,
                )
            )

        # ── Step 4: Deduplicate / merge overlapping spans ─────────────────────
        validated = self._merge_spans(validated)

        # ── Step 5: Build anonymiser operators ────────────────────────────────
        operators = self._build_operators(text, validated)

        # ── Step 6: Apply anonymisation ───────────────────────────────────────
        anon_result = self._anonymizer.anonymize(
            text=text,
            analyzer_results=validated,
            operators=operators,
        )

        # ── Step 7: Count stats ───────────────────────────────────────────────
        for r in validated:
            self._stats[r.entity_type] = self._stats.get(r.entity_type, 0) + 1

        token_map = self._token_store.to_dict() if self.mode == "tokenize" else None
        return anon_result.text, token_map

    @property
    def last_stats(self) -> dict:
        return dict(self._stats)

    # ── Context span finders ──────────────────────────────────────────────────

    def _find_context_spans(self, text: str) -> list[tuple[int, int, str]]:
        spans = []

        # 1. Context trigger phrases → name
        for m in NAME_TRIGGER.finditer(text):
            after = text[m.end():m.end() + 80].strip()
            nm = NAME_PATTERN.match(after)
            if nm:
                name = nm.group().strip()
                words = [w for w in re.split(r"[\s\-]", name) if w]
                # Deduplicate consecutive repeated words
                deduped = [words[0]] if words else []
                for w in words[1:]:
                    if w.lower() != deduped[-1].lower():
                        deduped.append(w)
                name = " ".join(deduped)

                if all(w.lower() not in NOT_A_NAME for w in deduped) and len(name) > 1:
                    if self._validator.is_name_phrase(name):
                        try:
                            start = text.index(name, m.end())
                            spans.append((start, start + len(name), "PERSON"))
                        except ValueError:
                            pass

        # 2. Spelled-out names: K-I-M-M-E-Y (min 5 letters)
        for m in SPELLED_NAME.finditer(text):
            spans.append((m.start(), m.end(), "PERSON"))

        # 3. Room numbers from conversational context
        for m in ROOM_CONTEXT.finditer(text):
            if m.lastindex:
                spans.append((m.start(1), m.end(1), "ROOM_NUMBER"))

        # 4. Standalone name lines
        for m in STANDALONE_NAME.finditer(text):
            name = m.group(1).strip()
            if any(c.isdigit() for c in name):
                continue
            words = [w for w in re.split(r"[\s\-]", name) if w]
            if (all(w.lower() not in NOT_A_NAME for w in words)
                    and all(len(w) >= 4 for w in words)
                    and self._validator.is_name_phrase(name)):
                spans.append((m.start(1), m.start(1) + len(name), "PERSON"))

        # 5. Name-as-question: "Elizabeth?" in check-in context
        for m in NAME_QUESTION_PAT.finditer(text):
            candidate = m.group(1).strip()
            if candidate in NOT_NAME_QUESTION or candidate.lower() in NOT_A_NAME:
                continue
            window = text[max(0, m.start()-150):min(len(text), m.end()+150)]
            in_db = None
            if self._validator._nd:
                try:
                    in_db = self._validator._nd.search(candidate)
                except Exception:
                    pass
            name_known = (
                self._validator.is_name(candidate) or
                (in_db is not None and (in_db.get("first_name") or in_db.get("last_name")))
            )
            if CHECKIN_CONTEXT.search(window) and name_known:
                spans.append((m.start(1), m.end(1), "PERSON"))

        return spans

    # ── Span utilities ────────────────────────────────────────────────────────

    def _merge_spans(self, results: list) -> list:
        """Remove overlapping spans, keeping highest-confidence one."""
        results = sorted(results, key=lambda r: (r.start, -(r.end - r.start), -r.score))
        merged, last_end = [], -1
        for r in results:
            if r.start >= last_end:
                merged.append(r)
                last_end = r.end
        return merged

    # ── Operator builder ──────────────────────────────────────────────────────

    def _build_operators(self, text: str, results: list) -> dict:
        """
        Build operator configs.
        Redact mode: replace with <ENTITY_TYPE>.
        Tokenize mode: each unique value gets its own stable token.
        Note: Presidio keys operators by entity_type, so two spans of the same
        type would share an operator. We work around this by pre-tokenizing all
        spans and using a custom anonymizer operator that looks up the token
        by the original span text.
        """
        if self.mode == "redact":
            return {"DEFAULT": OperatorConfig("replace", {"new_value": "<{entity_type}>"})}

        # Pre-build token map for every span
        for r in results:
            original = text[r.start:r.end]
            self._token_store.get_or_create(r.entity_type, original)

        # Use a lambda operator that looks up the correct token per span value
        token_store = self._token_store

        def _tokenize_operator(entity_type):
            """Returns an operator that maps original text -> its token."""
            return OperatorConfig(
                "custom",
                {
                    "lambda": lambda x, et=entity_type: token_store.get_or_create(et, x)
                },
            )

        # Build one operator per entity type
        entity_types = {r.entity_type for r in results}
        return {et: _tokenize_operator(et) for et in entity_types}
