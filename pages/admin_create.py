import base64
import os
import json, time
import random
import dash
from dash import html, dcc, Input, Output, State, callback, ctx, no_update
import dash_mantine_components as dmc
import dash_ag_grid as dag
import dash_iconify
import dash_ace
import xmltodict
from utils.db import db, Challenge
from utils.sigma_engine import parse_log_file, validate_sigma_rule
from utils.win_log_generator import generate_windows_security_logs,generate_windows_sysmon_logs
import random

dash.register_page(__name__, path="/admin/create", title="Create Challenge")

UPLOAD_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "challenges_logs",
)
os.makedirs(UPLOAD_DIR, exist_ok=True)

SIGMA_TMPL = """title: Detection Rule
status: experimental
description: Detect the attack event
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '\\cmd.exe'
    Commandline|contains|all:
      - "certutil"
      - "-f -decode"
      - "fi.b64"
  condition: selection
level: high
"""

def shuffle_list(data):
    """
    Shuffles the given list in place and returns it.
    """
    if not isinstance(data, list):
        raise TypeError("Input must be a list.")
    if len(data) < 2:
        return data  # No need to shuffle if list has 0 or 1 element
    
    random.shuffle(data)  # Shuffles in place
    return data

def _generate_fp_logs(source_type, count=4):
    events=[]
    if source_type == "windows_eventlog":
        events = generate_windows_security_logs(count)
    elif source_type == "windows_sysmon":
        events = generate_windows_sysmon_logs(count)

    return events


def _safe_str(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)
    return str(value)


def _first_present(ev, keys, default=""):
    for key in keys:
        value = ev.get(key)
        if value not in (None, "", [], {}):
            return value
    return default


def _collect_extra_fields(ev, used_keys=None):
    used_keys = set(used_keys or [])
    extras = []
    for key, value in (ev or {}).items():
        if key in used_keys:
            continue
        if value in (None, "", [], {}):
            continue
        extras.append((str(key), _safe_str(value)))
    extras.sort(key=lambda item: item[0].lower())
    return extras


def _event_to_grid_row(ev):
    record_id = _safe_str(_first_present(ev, ["EventRecordID", "RecordID", "Event.System.EventRecordID"]))
    event_id = _safe_str(_first_present(ev, ["EventID", "Event.System.EventID"]))
    time_created = _safe_str(
        _first_present(ev, ["TimeCreated", "Event.System.TimeCreated.#attributes.SystemTime"])
    )[:19]

    used_keys = {
        "EventRecordID", "RecordID", "Event.System.EventRecordID",
        "EventID", "Event.System.EventID",
        "TimeCreated", "Event.System.TimeCreated.#attributes.SystemTime",
    }

    extras = _collect_extra_fields(ev, used_keys)
    row = {
        "RecordID": record_id,
        "EventID": event_id,
        "TimeCreated": time_created,
        "AllFields": " | ".join(f"{k}: {v}" for k, v in extras),
    }

    for key, value in extras:
        row[key] = value

    return row


def _build_dynamic_column_defs(rows, preferred_fields=None):
    preferred_fields = preferred_fields or ["RecordID", "EventID", "TimeCreated", "AllFields"]
    fields = set()

    for row in (rows or []):
        fields.update(row.keys())

    ordered_fields = [field for field in preferred_fields if field in fields]
    dynamic_fields = sorted(field for field in fields if field not in preferred_fields)
    ordered_fields.extend(dynamic_fields)

    column_defs = []
    for field in ordered_fields:
        col = {
            "field": field,
            "headerName": "All Fields" if field == "AllFields" else field,
            "filter": True,
            "sortable": True,
            "resizable": True,
            "wrapText": field == "AllFields",
            #"autoHeight": field == "AllFields",
            "autoHeight": False,
        }
        if field == "AllFields":
            col["flex"] = 2
            col["minWidth"] = 420
        else:
            col["minWidth"] = 140
        column_defs.append(col)

    return column_defs

# ── Layout ────────────────────────────────────────────────────────────────────
def layout():
    return html.Div(
        [
            dcc.Store(id="ac-step", data=1),
            dcc.Store(id="ac-events", data=[]),
            dcc.Store(id="ac-logpath", data=""),
            dcc.Store(id="ac-tp-id", data=""),
            dcc.Store(id="ac-tp-event", data={}), # stores full TP event dict
            dcc.Store(id="ac-fp-ids", data=[]),
            dcc.Store(id="ac-fp-extra", data=[]), # stores socfaker selected FP events
            dcc.Store(id="ac-linked-fp-selected", data=[]), # stores selected linked FP row only if user selects it
            dcc.Store(id="ac-sigma-ok", data=False),
            dcc.Store(id="ac-sigma-res", data={}),
            html.Div(id="ac-guard"),
            html.Div(id="ac-wizard"),
        ]
    )

# ── Guard ─────────────────────────────────────────────────────────────────────
@callback(Output("ac-guard", "children"), Input("auth-store", "data"))
def guard(a):
    a = a or {}
    if not a.get("logged_in") or a.get("role") != "admin":
        return dmc.Alert("Admin access required.", color="red")
    return ""

# ── Wizard container ──────────────────────────────────────────────────────────
@callback(
    Output("ac-wizard", "children"),
    Input("ac-step", "data"),
    State("ac-events", "data"),
    State("ac-tp-id", "data"),
    State("ac-fp-ids", "data"),
    State("ac-sigma-ok", "data"),
    State("ac-sigma-res", "data"),
    State("ac-tp-event", "data"),
    State("auth-store", "data"),
)
def wizard(step, events, tp_id, fp_ids, sigma_ok, sigma_res, tp_event, a):    
    a = a or {}
    if not a.get("logged_in") or a.get("role") != "admin":
        return ""
    labels = [
        "Upload & Parse Log",
        "Select True Positive",
        "Select False Positives",
        "Metadata & Sigma Rule",
    ]
    stepper = dmc.Stepper(
        active=step - 1,
        mb="xl",
        children=[
            dmc.StepperStep(label=l, description=f"Step {i+1}")
            for i, l in enumerate(labels)
        ],
    )
    if step == 1:
        body = _s1()
    elif step == 2:
        body = _s2(events)
    elif step == 3:
        body = _s3(events, tp_id)
    else:
        body = _s4(tp_id, fp_ids, sigma_ok, sigma_res, tp_event)        

    return dmc.Stack(
        gap="lg",
        children=[dmc.Title("Create Challenge", order=2), stepper, body],
    )

# ── Step bodies ───────────────────────────────────────────────────────────────
def _s1():
    return dmc.Stack(
        gap="md",
        children=[
            dmc.Text("Upload a Windows Event Log (.evtx or .xml/.txt)", fw=600),
            dcc.Upload(
                id="ac-upload",
                accept=".evtx,.xml,.txt",
                children=dmc.Paper(
                    p="xl",
                    radius="md",
                    withBorder=True,
                    style={
                        "textAlign": "center",
                        "cursor": "pointer",
                        "borderStyle": "dashed",
                    },
                    children=[
                        dash_iconify.DashIconify(icon="tabler:upload", width=40),
                        dmc.Text("Click or drag & drop log file", mt="sm"),
                    ],
                ),
            ),
            dmc.Alert(id="ac-up-msg", style={"display": "none"}),
        ],
    )

def _s2(events):
    """Step 2: Select True Positive row. Includes a linked FP preview."""
    rows = [_event_to_grid_row(ev) for ev in (events or [])[:100]]
    columnDefs = _build_dynamic_column_defs(rows)

    return dmc.Stack(
        gap="md",
        children=[
            dmc.Alert(
                "Click the TRUE POSITIVE row (the attack event).",
                color="blue",
            ),
            dmc.Text(id="ac-tp-lbl", c="teal", fw=600),
            dag.AgGrid(
                id="ac-tp-grid",
                rowData=rows,
                columnDefs=columnDefs,
                columnSize="sizeToFit",
                dashGridOptions={
                    "rowSelection": {"mode": "singleRow"},
                    "animateRows": False,
                    "rowHeight": 28,
                },
                style={"height": "380px", "width": "100%"},
            ),
            dmc.Divider(label="Linked False Positive Event (same EventID)", labelPosition="center"),
            dmc.Alert(
                "A false positive event with the same EventID as the selected True Positive "
                "but different field values will be auto-generated below when you select a TP row. "
                "It will be added to the validation log only if you explicitly select it.",
                color="orange",
                mb="xs",
            ),
            dmc.Text(id="ac-linked-fp-lbl", c="orange", fw=600, fz="sm"),
            dag.AgGrid(
                id="ac-linked-fp-grid",
                rowData=[],
                columnDefs=columnDefs,
                columnSize="sizeToFit",
                dashGridOptions={
                    "rowSelection": {"mode": "singleRow"},
                    "animateRows": False,
                    "rowHeight": 28,
                },
                style={"height": "120px", "width": "100%"},
            ),
            dmc.Group(
                gap="sm",
                children=[
                    dmc.Button("← Back", id="ac-s2-back", variant="subtle", color="gray"),
                    dmc.Button("Next →", id="ac-s2-next", disabled=True),
                ],
            ),
        ],
    )

def _s3(events, tp_id):
    """Step 3: Select False Positives from uploaded log (TP excluded) + socfaker generated."""
    rows = []
    for ev in (events or [])[:100]:
        row = _event_to_grid_row(ev)
        if row.get("RecordID") == str(tp_id):
            continue
        rows.append(row)

    columnDefs = _build_dynamic_column_defs(rows)

    return dmc.Stack(
        gap="md",
        children=[
            dmc.Alert(
                "Select up to 5 FALSE POSITIVE rows (benign but similar events).",
                color="yellow",
            ),
            dmc.Text(id="ac-fp-lbl", c="orange", fw=600),
            dag.AgGrid(
                id="ac-fp-grid",
                rowData=rows,
                columnDefs=columnDefs,
                columnSize="sizeToFit",
                dashGridOptions={
                    "rowSelection": {"mode": "multiRow"},
                    "animateRows": False,
                    "rowHeight": 28,
                },
                style={"height": "300px", "width": "100%"},
            ),
            dmc.Divider(label="Generate Additional False Positives via SocFaker", labelPosition="center"),
            dmc.Alert(
                "Events from the uploaded log are NOT shown here. "
                "Choose a source type and generate synthetic false positive events.",
                color="blue",
            ),
            dmc.Group(
                align="flex-end",
                gap="sm",
                children=[
                    dmc.Select(
                        id="ac-socfaker-source",
                        label="Log Source",
                        data=[
                            {"value": "windows_eventlog", "label": "Windows Event Log"},
                            {"value": "windows_sysmon", "label": "Windows Sysmon"},
                        ],
                        value="windows_eventlog",
                        w=220,
                    ),
                    dmc.Button(
                        "Generate Events",
                        id="ac-socfaker-gen-btn",
                        variant="outline",
                        leftSection=dash_iconify.DashIconify(icon="tabler:refresh", width=16),
                    ),
                ],
            ),
            dmc.Text(id="ac-socfaker-lbl", c="blue", fw=600, fz="sm"),
            dag.AgGrid(
                id="ac-socfaker-grid",
                rowData=[],
                columnDefs=columnDefs,
                columnSize="sizeToFit",
                dashGridOptions={
                    "rowSelection": {"mode": "multiRow"},
                    "animateRows": False,
                    "rowHeight": 28,
                },
                style={"height": "220px", "width": "100%"},
            ),
            dmc.Group(
                gap="sm",
                children=[
                    dmc.Button("← Back", id="ac-s3-back", variant="subtle", color="gray"),
                    dmc.Button("Next →", id="ac-s3-next"),
                ],
            ),
        ],
    )


def _s4(tp_id, fp_ids, sigma_ok, sigma_res, tp_event):
    msg = (sigma_res or {}).get("message", "")
    return dmc.Grid(
        children=[
            dmc.GridCol(
                span={"base": 12, "md": 7},
                children=dmc.Stack(
                    gap="md",
                    children=[
                        dmc.TextInput(
                            id="ac-title",
                            label="Title",
                            placeholder="Log Injection Detection",
                        ),
                        dmc.Select(
                            id="ac-category",
                            label="Category",
                            data=[
                                "Windows Events",
                                "SIEM",
                                "Threat Hunting",
                                "Log Analysis",
                                "Network",
                            ],
                            value="Windows Events",
                        ),
                        dmc.Select(
                            id="ac-difficulty",
                            label="Difficulty",
                            data=["easy", "medium", "hard", "expert"],
                            value="medium",
                        ),
                        dmc.NumberInput(
                            id="ac-points",
                            label="Points",
                            value=100,
                            min=10,
                            step=10,
                        ),
                        dmc.Textarea(
                            id="ac-description",
                            label="Description",
                            minRows=3,
                            placeholder="Describe the challenge.",
                        ),
                        dmc.Divider(
                            label="Reference Sigma Rule",
                            labelPosition="center",
                        ),
                        dash_ace.DashAceEditor(
                            id="ac-sigma",
                            theme="github",
                            mode="yaml",
                            tabSize=2,
                            width="100%",
                            height="250px",
                            value=SIGMA_TMPL,
                            style={"border": "1px solid #ced4da", "marginBottom": "10px"},
                        ),
                        dmc.Button(
                            "Validate Sigma",
                            id="ac-val-btn",
                            variant="outline",
                        ),
                        dmc.Alert(
                            id="ac-val-msg",
                            style={"display": "block" if msg else "none"},
                            children=msg,
                            color="green" if sigma_ok else "red",
                        ),
                        dmc.Alert(
                            id="ac-save-msg",
                            style={"display": "none"},
                        ),
                        dmc.Group(
                            gap="sm",
                            children=[
                                dmc.Button("← Back", id="ac-s4-back", variant="subtle", color="gray"),
                                dmc.Button(
                                    "Publish Challenge",
                                    id="ac-pub-btn",
                                    color="green",
                                    disabled=not sigma_ok,
                                    leftSection=dash_iconify.DashIconify(
                                        icon="tabler:check", width=16
                                    ),
                                ),
                            ],
                        ),
                    ],
                ),
            ),
            dmc.GridCol(
                span={"base": 12, "md": 5},
                children=dmc.Paper(
                    p="md",
                    radius="md",
                    withBorder=True,
                    children=dmc.Stack(
                        gap="xs",
                        children=[
                            dmc.Title("Summary", order=4),
                            dmc.Divider(),
                            dmc.Group(
                                justify="space-between",
                                children=[
                                    dmc.Text(
                                        "TP RecordID:",
                                        fz="sm",
                                        c="dimmed",
                                    ),
                                    dmc.Badge(
                                        str(tp_id) if tp_id else "Not set",
                                        color="teal",
                                    ),
                                ],
                            ),
                            dmc.Group(
                                justify="space-between",
                                children=[
                                    dmc.Text(
                                        "False Positives:",
                                        fz="sm",
                                        c="dimmed",
                                    ),
                                    dmc.Text(
                                        str(len(fp_ids or [])),
                                        fz="sm",
                                    ),
                                ],
                            ),
                            dmc.Group(
                                justify="space-between",
                                children=[
                                    dmc.Text(
                                        "Sigma Valid:",
                                        fz="sm",
                                        c="dimmed",
                                    ),
                                    dmc.Badge(
                                        "Yes" if sigma_ok else "No",
                                        color="green" if sigma_ok else "red",
                                    ),
                                ],
                            ),
                            dmc.Divider(label="True Positive Event", labelPosition="center"),
                            dmc.ScrollArea(
                                h=260,
                                offsetScrollbars=True,
                                children=dmc.Code(
                                    block=True,
                                    children=json.dumps(tp_event or {}, indent=2),
                                    style={"whiteSpace": "pre-wrap", "fontSize": "12px"},
                                ),
                            ),
                        ],
                    ),
                ),
            ),
        ]
    )

# ── Callbacks ─────────────────────────────────────────────────────────────────
@callback(
    Output("ac-step", "data", allow_duplicate=True),
    Output("ac-events", "data", allow_duplicate=True),
    Output("ac-logpath", "data", allow_duplicate=True),
    Output("ac-up-msg", "children", allow_duplicate=True),
    Output("ac-up-msg", "color", allow_duplicate=True),
    Output("ac-up-msg", "style", allow_duplicate=True),
    Input("ac-upload", "contents"),
    State("ac-upload", "filename"),
    prevent_initial_call=True,
)
def upload(contents, filename):
    if not contents:
        return no_update, no_update, no_update, "", "red", {"display": "none"}
    _, b64 = contents.split(",", 1)
    path = os.path.join(UPLOAD_DIR, filename.replace(" ", "_"))
    with open(path, "wb") as f:
        f.write(base64.b64decode(b64))
    evts = parse_log_file(path)
    print("PARSED RECORDS SAMPLE:", evts[:2] if evts else "EMPTY")
    if not evts:
        return (
            no_update,
            [],
            path,
            "Cannot parse file — ensure valid .evtx or .xml",
            "red",
            {"display": "block"},
        )
    return (
        2,
        evts,
        path,
        f"Parsed {len(evts)} events from {filename}",
        "green",
        {"display": "block"},
    )

# Step 2: set TP from selected row + generate linked FP preview and clear previous linked FP selection
@callback(
    Output("ac-tp-id", "data", allow_duplicate=True),
    Output("ac-tp-event", "data", allow_duplicate=True),
    Output("ac-tp-lbl", "children", allow_duplicate=True),
    Output("ac-s2-next", "disabled", allow_duplicate=True),
    Output("ac-linked-fp-grid", "rowData"),
    Output("ac-linked-fp-grid", "columnDefs"),
    Output("ac-linked-fp-lbl", "children"),
    Output("ac-linked-fp-selected", "data", allow_duplicate=True),
    Input("ac-tp-grid", "selectedRows"),
    State("ac-events", "data"),
    prevent_initial_call=True,
)
def sel_tp(selected_rows, all_events):
    print("SELECTED ROWS:", selected_rows)
    if not selected_rows:
        return no_update, no_update, no_update, True, [], [], "", []
    row = selected_rows[0]
    rid = row.get("RecordID")
    if not rid:
        return no_update, no_update, no_update, True, [], [], "", []

    tp_event = {}
    for ev in (all_events or []):
        if str(ev.get("EventRecordID", ev.get("Event.System.EventRecordID", ""))) == str(rid):
            tp_event = ev
            break

    tp_eid = row.get("EventID", "")
    fake_rid = str(int(rid) + 200)
    linked_fp_event = dict(tp_event or {})
    linked_fp_event.update({
        "EventRecordID": fake_rid,
        "EventID": tp_eid,
        "TimeCreated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "svchost.exe -k netsvcs -p -s Schedule",
    })
    linked_fp_row = _event_to_grid_row(linked_fp_event)
    linked_fp_column_defs = _build_dynamic_column_defs([linked_fp_row])

    lbl = (
        f"✓ Linked FP auto-generated — same EventID ({tp_eid}), "
        f"different Image & CommandLine (RecordID: {fake_rid}). "
        f"Select this row if you want to include it in validation."
    )

    return (
        rid,
        tp_event,
        f"✓ True Positive: EventRecordID = {rid}",
        False,
        [linked_fp_row],
        linked_fp_column_defs,
        lbl,
        [],
    )

# Step 2: store selected linked FP row only if user selects it
@callback(
    Output("ac-linked-fp-selected", "data", allow_duplicate=True),
    Input("ac-linked-fp-grid", "selectedRows"),
    prevent_initial_call=True,
)
def sel_linked_fp(selected_rows):
    if not selected_rows:
        return []
    return selected_rows[:1]

# Step 3: set FP IDs from multi-select (uploaded log events)
@callback(
    Output("ac-fp-ids", "data", allow_duplicate=True),
    Output("ac-fp-lbl", "children", allow_duplicate=True),
    Input("ac-fp-grid", "selectedRows"),
    prevent_initial_call=True,
)
def sel_fp(selected_rows):
    if not selected_rows:
        return [], "False Positives (0/5):"
    ids = [r.get("RecordID") for r in selected_rows if r.get("RecordID")]
    ids = ids[:5]
    label = f"False Positives ({len(ids)}/5): {', '.join(ids)}"
    return ids, label

# Step 3: Generate socfaker events based on selected source type
@callback(
    Output("ac-socfaker-grid", "rowData"),
    Output("ac-socfaker-grid", "columnDefs"),
    Output("ac-socfaker-lbl", "children"),
    Input("ac-socfaker-gen-btn", "n_clicks"),
    State("ac-socfaker-source", "value"),
    State("ac-events", "data"),
    prevent_initial_call=True,
)
def generate_socfaker_events(n, source_type, uploaded_events):
    if not n:
        return [], [], ""
    source_type = source_type or "windows_eventlog"

    uploaded_rids = set()
    for ev in (uploaded_events or []):
        uploaded_rids.add(str(ev.get("EventRecordID", ev.get("Event.System.EventRecordID", ""))))

    raw_events = _generate_fp_logs(source_type, count=6)

    rows = []
    for i, norm in enumerate(raw_events):
        record_id = str(norm.get("RecordID", norm.get("EventRecordID", "")))
        if record_id in uploaded_rids:
            norm["RecordID"] = f"SF-{source_type[:3].upper()}-{i+1}-{int(time.time())}"
        rows.append(_event_to_grid_row(norm))

    column_defs = _build_dynamic_column_defs(rows)

    source_labels = {
        "windows_eventlog": "Windows Event Log",
        "windows_sysmon": "Windows Sysmon",
    }
    lbl = f"Generated {len(rows)} synthetic events from {source_labels.get(source_type, source_type)}. Select rows to add as FPs."
    return rows, column_defs, lbl

# Step 3: store selected socfaker FP rows into ac-fp-extra store
@callback(
    Output("ac-fp-extra", "data", allow_duplicate=True),
    Input("ac-socfaker-grid", "selectedRows"),
    prevent_initial_call=True,
)
def sel_socfaker_fp(selected_rows):
    if not selected_rows:
        return []
    return selected_rows[:5]

@callback(
    Output("ac-step", "data", allow_duplicate=True),
    Input("ac-s2-next", "n_clicks"),
    State("ac-tp-id", "data"),
    prevent_initial_call=True,
)
def s2next(n, tp_id):
    if not n or not tp_id:
        return no_update
    return 3

@callback(
    Output("ac-step", "data", allow_duplicate=True),
    Input("ac-s3-next", "n_clicks"),
    prevent_initial_call=True,
)
def s3next(n):
    return 4 if n else no_update

@callback(
    Output("ac-step", "data", allow_duplicate=True),
    Input("ac-s2-back", "n_clicks"),
    prevent_initial_call=True,
)
def s2back(n):
    return 1 if n else no_update

@callback(
    Output("ac-step", "data", allow_duplicate=True),
    Input("ac-s3-back", "n_clicks"),
    prevent_initial_call=True,
)
def s3back(n):
    return 2 if n else no_update

@callback(
    Output("ac-step", "data", allow_duplicate=True),
    Input("ac-s4-back", "n_clicks"),
    prevent_initial_call=True,
)
def s4back(n):
    return 3 if n else no_update

# Validate Sigma Button click
@callback(
    Output("ac-sigma-ok", "data", allow_duplicate=True),
    Output("ac-sigma-res", "data", allow_duplicate=True),
    Output("ac-val-msg", "children", allow_duplicate=True),
    Output("ac-val-msg", "color", allow_duplicate=True),
    Output("ac-val-msg", "style", allow_duplicate=True),
    Output("ac-pub-btn", "disabled", allow_duplicate=True),
    Output("ac-logpath", "data", allow_duplicate=True),
    Input("ac-val-btn", "n_clicks"),
    State("ac-sigma", "value"),
    State("ac-logpath", "data"),
    State("ac-tp-id", "data"),
    State("ac-fp-ids", "data"),
    State("ac-fp-extra", "data"),
    State("ac-linked-fp-selected", "data"),
    State("ac-events", "data"),
    State("ac-tp-event", "data"),
    prevent_initial_call=True,
)
def val_sigma(n, yaml_text, logpath, tp_id, fp_ids, fp_extra, linked_fp_selected, all_events, tp_event):
    if not n or not yaml_text or not logpath:
        return False, {}, "", "gray", {"display": "none"}, True, no_update
    if not os.path.exists(logpath):
        return False, {}, "Log file missing.", "red", {"display": "block"}, True, no_update

    keep_ids = set([str(tp_id)] + [str(x) for x in (fp_ids or [])])
    filtered = [
        ev for ev in (all_events or [])
        if str(ev.get("Event.System.EventRecordID", ev.get("EventRecordID", ""))) in keep_ids
    ]

    if linked_fp_selected:
        fp = linked_fp_selected[0]
        linked_fp = {
            "EventRecordID": fp.get("RecordID", ""),
            "EventID": fp.get("EventID", ""),
            "TimeCreated": fp.get("TimeCreated", ""),
        }
        for key, value in fp.items():
            if key in {"RecordID", "EventID", "TimeCreated", "AllFields"}:
                continue
            if value in (None, "", [], {}):
                continue
            linked_fp[key] = value
        filtered.append(linked_fp)

    for fp in (fp_extra or []):
        synthetic_ev = {
            "EventRecordID": fp.get("RecordID", ""),
            "EventID": fp.get("EventID", ""),
            "TimeCreated": fp.get("TimeCreated", ""),
        }
        for key, value in fp.items():
            if key in {"RecordID", "EventID", "TimeCreated", "AllFields"}:
                continue
            if value in (None, "", [], {}):
                continue
            synthetic_ev[key] = value
        filtered.append(synthetic_ev)

    if not filtered:
        return (
            False, {},
            "No matching events found for selected TP/FP IDs. Go back and re-select.",
            "red", {"display": "block"}, True, no_update,
        )

    #Randomize the logs list before writing to disk
    shuffle_list(filtered)

    base = os.path.splitext(os.path.basename(logpath))[0]
    small_filename = f"{base}_challenge_{int(time.time())}.json"
    small_path = os.path.join(UPLOAD_DIR, small_filename)
    with open(small_path, "w") as f:
        json.dump(filtered, f, indent=2)

    res = validate_sigma_rule(yaml_text, small_path)
    ok = res["ok"]
    msg = res["message"]

    if ok:
        mid = str((res.get("matched_ids") or [""])[0])
        if mid != str(tp_id):
            ok = False
            msg = (
                f"Rule matched RecordID={mid}, but TP is {tp_id}. "
                "Adjust rule to target only the true positive."
            )

    color = "green" if ok else ("red" if res.get("count", 0) == 0 else "orange")
    new_logpath = small_path if ok else no_update

    return ok, res, msg, color, {"display": "block"}, not ok, new_logpath

@callback(
    Output("ac-save-msg", "children", allow_duplicate=True),
    Output("ac-save-msg", "color", allow_duplicate=True),
    Output("ac-save-msg", "style", allow_duplicate=True),
    Output("ac-pub-btn", "disabled"),
    Output("ac-step", "data", allow_duplicate=True),
    Input("ac-pub-btn", "n_clicks"),
    State("ac-title", "value"),
    State("ac-category", "value"),
    State("ac-difficulty", "value"),
    State("ac-points", "value"),
    State("ac-description", "value"),
    State("ac-sigma", "value"),
    State("ac-logpath", "data"),
    State("ac-tp-id", "data"),
    State("ac-sigma-res", "data"),
    State("auth-store", "data"),
    prevent_initial_call=True,
)
def publish(n, title, cat, diff, pts, desc, sigma, logpath, tp_id, sigma_res, a):
    ac_pub_btn_disabled = False
    ac_step = no_update
    if not n:
        return "", "green", {"display": "none"}, ac_pub_btn_disabled, ac_step
    if not title or not desc:
        return "Title and description required.", "red", {"display": "block"}, ac_pub_btn_disabled, ac_step
    a = a or {}
    mids = (sigma_res or {}).get("matched_ids", [])
    ans = str(mids[0]) if mids else str(tp_id)
    ch = Challenge(
        title=title,
        description=desc,
        category=cat or "",
        difficulty=diff or "medium",
        points=int(pts or 100),
        flag=f"CTF{{{ans}}}",
        log_file_path=logpath or "",
        sigma_rule=sigma or "",
        answer_event_record_id=ans,
        status="published",
        author_id=a.get("user_id"),
    )
    db.session.add(ch)
    db.session.commit()
    ac_pub_btn_disabled = True # If publish button remain true multiple copies of challenge might get submit by mistake when clicked again
    ac_step = 5 #This is just to show step 4 complete
    return (
        f"Challenge '{title}' published (ID: {ch.id})!",
        "green",
        {"display": "block"},
        ac_pub_btn_disabled,
        ac_step,
    )