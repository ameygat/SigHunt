import json
import os, re, sqlite3, xml.etree.ElementTree as ET
from typing import List, Dict
from Evtx.Evtx import Evtx
try:
    import yaml
    from sigma.rule import SigmaRule
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaDetection#, SigmaDetectionItem
    #from sigma.modifiers import SigmaEndswithModifier, SigmaStartswithModifier, SigmaContainsModifier, SigmaAllModifier
    #from sigma.exceptions import SigmaDetectionError,SigmaLogsourceError,SigmaTitleError

    PYSIGMA_OK = True
except ImportError:
    PYSIGMA_OK = False

def flatten_evtx_record(xml_str):
    try:
        root = ET.fromstring(xml_str)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        flat_event = {}

        system = root.find('ns:System', ns)
        if system is not None:
            for child in system:
                tag = child.tag.split('}')[-1]
                flat_event[tag] = child.text
                if tag == "TimeCreated":
                    flat_event[tag] = child.attrib.get('SystemTime')

        event_data = root.find('ns:EventData', ns)
        if event_data is not None:
            for data in event_data.findall('ns:Data', ns):
                name = data.attrib.get('Name')
                if name:
                    flat_event[name] = data.text
        return flat_event
    except Exception as e:
        print(f"Error:{str(e)}")
        return {}
    
def load_logs(path):
    if not os.path.exists(path): return []
    events = []
    try:
        with Evtx(path) as log:
            for record in log.records():
                events.append(flatten_evtx_record(record.xml()))
    except Exception as e:
        print(f"Log Error: {e}")
    return events

def load_logs_xml(path):
    events = []
    if os.path.exists(path):
        try:
            tree = ET.parse(path)
            root = tree.getroot()

            # The root is usually <Events>, and we iterate over each <Event>
            for event_element in root.findall('.//{*}Event'):
                event_data = {}
                
                # 1. Parse System Data (ID, RecordID, Time)
                system = event_element.find('{*}System')
                if system is not None:
                    event_id = system.find('{*}EventID')
                    record_id = system.find('{*}EventRecordID')
                    
                    if event_id is not None:
                        event_data['EventID'] = event_id.text
                    if record_id is not None:
                        event_data['EventRecordID'] = record_id.text

                # 2. Parse EventData (The payload fields like ScriptBlockText)
                event_data_tags = event_element.find('{*}EventData')
                if event_data_tags is not None:
                    for data in event_data_tags.findall('{*}Data'):
                        name = data.get('Name')
                        if name:
                            event_data[name] = data.text
                
                events.append(event_data)

        except Exception as e:
            print(f"Log Error: {e}")

    return events

def parse_log_file(filepath: str) -> List[Dict]:
    ext = os.path.splitext(filepath)[1].lower()
    events = []
    if ext == ".evtx":
        try:
            events = load_logs(filepath)
        except Exception as e:
            print(f"[EVTX] {e}")
    elif ext == ".xml":
        try:
            events = load_logs_xml(filepath)
        except Exception as e:
            print(f"[XML] {e}")
    elif ext == ".json":
        try:
            with open(filepath, 'r') as file:
                events = json.load(file)
        except Exception as e:
            print(f"[XML] {e}")
    return events

def _parse_xml(filepath: str) -> List[Dict]:
    events = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if not content.strip().startswith("<Events"):
            content = f"<Events>{content}</Events>"
        root = ET.fromstring(content)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        for event in root.iter("{http://schemas.microsoft.com/win/2004/08/events/event}Event"):
            flat = {}
            sys = event.find("e:System", ns)
            if sys is not None:
                for child in sys:
                    tag = child.tag.split("}")[-1]
                    flat[tag] = child.text or ""
                    for k, v in child.attrib.items():
                        flat[f"{tag}.{k}"] = v
            evdata = event.find("e:EventData", ns)
            if evdata is not None:
                for d in evdata:
                    flat[d.get("Name", "Data")] = d.text or ""
            events.append(flat)
    except Exception as e:
        print(f"[XML] {e}")
    return events


def _flatten(obj, prefix="") -> Dict:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten(v, f"{prefix}{i}."))
    else:
        out[prefix.rstrip(".")] = str(obj) if obj is not None else ""
    return out


def validate_sigma_rule(sigma_yaml: str, log_filepath: str) -> Dict:
    # Load events — support both JSON (filtered) and EVTX/XML (original upload)
    if log_filepath.endswith(".json"):
        with open(log_filepath, "r") as f:
            events = json.load(f)   # already a list of dicts
    else:
        events = parse_log_file(log_filepath)  # parse EVTX/XML as before

    if not events:
        return {"ok": False, "count": 0, "matched_ids": [], "message": "No events parsed from log", "matched_events": []}
        
    if PYSIGMA_OK:
        return _validate_pysigma(sigma_yaml, events)
    return _validate_keyword(sigma_yaml, events)

def manual_sigma_match(sigma_rule_collection, log_events):
    from sigma.types import SigmaString
    matches = []

    def build_pattern(v, modifiers):
        """Build a regex pattern respecting endswith/startswith modifiers."""
        mod_types = [type(m).__name__ for m in modifiers]
        val_str = str(v).lower()
        # Bug 1 fix: re.escape then replace \* (single backslash) with .*
        pattern = re.escape(val_str).replace(r'\*', '.*')
        if 'SigmaEndswithModifier' in mod_types:
            pattern = pattern + '$'
        elif 'SigmaStartswithModifier' in mod_types:
            pattern = '^' + pattern
        # contains / no modifier → plain re.search (substring) — no anchoring needed
        return pattern

    for rule in sigma_rule_collection.rules:
        detections = rule.detection.detections

        for event in log_events:
            # Bug 3 fix: case-insensitive key lookup
            event_lower = {k.lower(): v for k, v in event.items()}

            for det_name, detection_obj in detections.items():
                if isinstance(detection_obj, SigmaDetection):
                    all_items_match = True

                    for item in detection_obj.detection_items:
                        field = item.field
                        values = item.value if isinstance(item.value, list) else [item.value]
                        modifiers = item.modifiers  # Bug 2 fix: read modifiers

                        event_val = str(event_lower.get(field.lower(), "")).lower()

                        # Bug 2 fix: check if ALL modifier is present
                        mod_type_names = [type(m).__name__ for m in modifiers]
                        use_all = 'SigmaAllModifier' in mod_type_names

                        if use_all:
                            # contains|all → every value must match (AND logic)
                            item_match = all(
                                bool(re.search(build_pattern(v, modifiers), event_val))
                                for v in values
                            )
                        else:
                            # Default → any one value must match (OR logic)
                            item_match = any(
                                bool(re.search(build_pattern(v, modifiers), event_val))
                                for v in values
                            )

                        if not item_match:
                            all_items_match = False
                            break

                    if all_items_match:
                        matches.append(event)
                        break

    return matches

def manual_sigma_match_old(sigma_rule_collection, log_events):
    """
    Manually parses the pySigma detection items and matches them against logs.
    """
    matches = []

    for rule in sigma_rule_collection.rules:
        # Get the 'detections' attribute from the rule
        detections = rule.detection.detections 
        
        for event in log_events:
            # A rule usually has multiple named detections (e.g., 'selection')
            for det_name, detection_obj in detections.items():
                # Check if detection_obj is a SigmaDetection
                if isinstance(detection_obj, SigmaDetection):
                    all_items_match = True
                    
                    # Each Detection has a list of SigmaDetectionItem objects
                    for item in detection_obj.detection_items:
                        field = item.field
                        # value could be a list or a single SigmaString/SigmaNumber
                        values = item.value if isinstance(item.value, list) else [item.value]
                        
                        
                        event_val = str(event.get(f"{field}", "")).lower()
                        item_match = False
                        for v in values:
                            # 1. Convert Sigma value to a string
                            val_str = str(v).lower()
                            
                            # 2. Escape regex special chars (like parens), but keep asterisks as wildcards
                            # Then replace '*' with '.*' (the regex equivalent)
                            pattern = re.escape(val_str).replace(r'\*', '.*')
                            
                            # 3. Match using regex
                            if re.search(pattern, event_val):
                                item_match = True
                                break
                            
                    if not item_match:
                        all_items_match = False
                        break

                    if all_items_match:
                        matches.append(event)
                        break # Found a match for this event in this rule
    return matches

def _validate_pysigma_old(sigma_yaml: str, events: List[Dict]) -> Dict:
    try:
        rule       = SigmaRule.from_yaml(sigma_yaml)
        collection = SigmaCollection([rule])
        backend    = sqliteBackend()
        queries    = backend.convert(collection)

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        cur  = conn.cursor()

        cols      = list(events[0].keys())
        safe_cols = [re.sub(r"[^a-zA-Z0-9_]", "_", c) for c in cols]
        col_defs  = ", ".join(f'"{c}" TEXT' for c in safe_cols)
        cur.execute(f"CREATE TABLE logs ({col_defs})")
        for ev in events:
            vals = [ev.get(c, "") for c in cols]
            cur.execute(f"INSERT INTO logs VALUES ({','.join(['?']*len(safe_cols))})", vals)

        matched = []
        for q in queries:
            try:
                cur.execute(q)
                matched = [dict(r) for r in cur.fetchall()]
            except Exception:
                pass
        conn.close()

        matched_ids = [str(m.get("EventRecordID", m.get("System_EventRecordID", ""))) for m in matched]
        return _result(len(matched), matched_ids, matched)
    except Exception as e:
        return {"ok": False, "count": 0, "matched_ids": [], "message": f"Sigma error: {e}", "matched_events": []}



def _validate_pysigma(sigma_yaml: str, events: List[Dict]) -> Dict:
    try:
        user_parsed = yaml.safe_load(sigma_yaml)
        rule_collection = SigmaCollection.from_dicts([user_parsed])
        matched = manual_sigma_match(sigma_rule_collection=rule_collection,log_events=events)

        matched_ids = [str(m.get("EventRecordID", m.get("System_EventRecordID", ""))) for m in matched]
        return _result(len(matched), matched_ids, matched)
    except Exception as e:
        return {"ok": False, "count": 0, "matched_ids": [], "message": f"Sigma error: {e}", "matched_events": []}


def _validate_keyword(sigma_yaml: str, events: List[Dict]) -> Dict:
    #import pdb;pdb.set_trace()
    try:
        import yaml as _yaml
        rule = _yaml.safe_load(sigma_yaml)
    except Exception as e:
        return {"ok": False, "count": 0, "matched_ids": [], "message": f"YAML error: {e}", "matched_events": []}

    keywords = []
    for k, v in rule.get("detection", {}).items():
        if k == "condition":
            continue
        if isinstance(v, dict):
            for val in v.values():
                if isinstance(val, list): keywords.extend(str(x) for x in val)
                elif val: keywords.append(str(val))
        elif isinstance(v, list):
            keywords.extend(str(x) for x in v)

    if not keywords:
        return {"ok": False, "count": 0, "matched_ids": [], "message": "No detection keywords in rule", "matched_events": []}

    matched = [ev for ev in events if all(kw.lower() in " ".join(str(v) for v in ev.values()).lower() for kw in keywords)]
    matched_ids = [str(m.get("EventRecordID", m.get("Event.System.EventRecordID", ""))) for m in matched]
    return _result(len(matched), matched_ids, matched)


def _result(count, matched_ids, matched_events):
    if count == 0:
        msg = "Rule matched 0 events — broaden your detection criteria"
    elif count == 1:
        msg = f"✓ Exactly 1 event matched — EventRecordID: {matched_ids[0]}"
    else:
        ids_str = ", ".join(matched_ids[:5])
        msg = f"Rule too broad — matched {count} events: [{ids_str}]"
    return {"ok": count == 1, "count": count, "matched_ids": matched_ids, "message": msg, "matched_events": matched_events}
