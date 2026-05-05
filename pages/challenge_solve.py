import os, dash
from dash import html, dcc, Input, Output, State, callback
import dash_mantine_components as dmc
import dash_iconify
from utils.db import db, Challenge, Submission, User
from utils.sigma_engine import validate_sigma_rule, parse_log_file
import dash_ace
dash.register_page(__name__, path_template="/challenge/<challenge_id>", title="Solve")

TEMPLATE = """title: My Detection Rule
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: high
"""

def layout(challenge_id=None):
    return html.Div([
        dcc.Store(id="sc-chal-id", data=challenge_id),
        dcc.Store(id="sc-vresult", data={}),
        html.Div(id="sc-body"),
    ])

@callback(Output("sc-body","children"),
          Input("auth-store","data"), Input("sc-chal-id","data"))
def render(auth_data, cid):
    a = auth_data or {}
    if not a.get("logged_in"):
        return dmc.Alert("Please log in.", color="red")
    ch = Challenge.query.get(int(cid)) if cid else None
    if not ch or ch.status != "published":
        return dmc.Alert("Challenge not found.", color="red")
    uid = a["user_id"]
    done = Submission.query.filter_by(user_id=uid,challenge_id=ch.id,is_correct=True).first()
    log_lines = []
    if ch.log_file_path and os.path.exists(ch.log_file_path):
        evts = parse_log_file(ch.log_file_path)
        # for ev in evts[:60]:
        #     #rid  = ev.get("EventRecordID",  ev.get("System.EventRecordID",""))
        #     eid  = ev.get("EventID",        ev.get("System.EventID",""))
        #     t    = str(ev.get("TimeCreated",ev.get("System.TimeCreated.SystemTime","")))[:19]
        #     comp = ev.get("Computer",       ev.get("System.Computer",""))
        #     img = str(ev.get("Image", ev.get("Event.EventData.Image", "")))[-40:]
        #     cmd = str(ev.get("CommandLine", ev.get("Event.EventData.CommandLine", "")))#[:60] #get first 60 charter            
        #     log_lines.append(f"[{t}] EventID={eid} Host={comp}  ")
        for ev in evts[:60]:
            t = str(ev.get("TimeCreated",ev.get("System.TimeCreated.SystemTime","")))[:19]
            eid  = ev.get("EventID",        ev.get("System.EventID",""))
            comp = ev.get("Computer",       ev.get("System.Computer",""))
            #ev.pop('EventRecordID') # temp remove for debugging in prod we dont want tho show EventRecordID to user
            log_lines.append(f"[{t}] EventID={eid} Host={comp} {ev}" )

    return dmc.Stack(gap="lg",children=[
        dmc.Anchor("← Back",href="/challenges",size="sm"),
        dmc.Group(justify="space-between",children=[
            dmc.Title(ch.title,order=2),
            dmc.Group(gap="xs",children=[
                dmc.Badge(ch.category,variant="dot"),
                dmc.Badge(ch.difficulty.upper(),
                    color={"easy":"green","medium":"yellow","hard":"orange","expert":"red"}.get(ch.difficulty,"gray"),
                    variant="light"),
                dmc.Badge(f"{ch.points} pts",color="blue",variant="outline"),
            ]),
        ]),
        dmc.Alert("✓ Already solved!",color="green",style={"display":"block" if done else "none"}),
        dmc.Grid(children=[
            dmc.GridCol(span={"base":12,"md":6},children=dmc.Paper(p="md",radius="md",withBorder=True,children=[
                dmc.Title("Description",order=4,mb="xs"),
                dmc.Text(ch.description),
                dmc.Divider(my="md"),
                dmc.Title("Log Events (first 60)",order=4,mb="xs"),
                dmc.ScrollArea(h=300,children=dmc.Code(
                    "\n".join(log_lines) if log_lines else "No log file.",block=True)),
            ])),
            dmc.GridCol(span={"base":12,"md":6},children=dmc.Paper(p="md",radius="md",withBorder=True,
                children=dmc.Stack(gap="sm",children=[
                    dmc.Title("Write Your Sigma Rule",order=4),
                    dmc.Text("Craft a rule that matches exactly 1 event. That EventRecordID is your answer.",
                             size="sm",c="dimmed"),
                    #dmc.Textarea(id="sc-sigma",label="Sigma Rule (YAML)",value=TEMPLATE,minRows=12,autosize=True,styles={"input":{"fontFamily":"monospace","fontSize":"13px"}}),
                    dmc.Text("Sigma Rule (YAML)"),
                    dash_ace.DashAceEditor(
                        id="sc-sigma",
                        theme="github", mode="yaml", tabSize=2, width="100%", height="250px",
                        value = TEMPLATE,
                        style={"border": "1px solid #ced4da", "marginBottom": "10px"}
                    ),                                 
                    dmc.Group(gap="sm",children=[
                        dmc.Button("Validate Rule",id="sc-validate-btn",variant="outline",
                                   leftSection=dash_iconify.DashIconify(icon="tabler:code",width=16)),
                        dmc.Button("Submit Solution",id="sc-submit-btn",disabled=True,
                                   leftSection=dash_iconify.DashIconify(icon="tabler:flag",width=16)),
                    ]),
                    html.Div(id="sc-val-msg"),
                    html.Div(id="sc-sub-msg"),
                ])
            )),
        ]),
    ])

@callback(
    Output("sc-vresult",    "data"),
    Output("sc-val-msg",    "children"),
    Output("sc-submit-btn", "disabled"),
    Input("sc-validate-btn","n_clicks"),
    State("sc-sigma",       "value"),
    State("sc-chal-id",     "data"),
    prevent_initial_call=True,
)
def validate(n, yaml_text, cid):
    if not n: return {}, "", True
    ch = Challenge.query.get(int(cid)) if cid else None
    if not ch or not ch.log_file_path or not os.path.exists(ch.log_file_path):
        return {}, dmc.Alert("Log file unavailable.",color="orange"), True
    res = validate_sigma_rule(yaml_text, ch.log_file_path)
    color = "green" if res["ok"] else ("red" if res["count"]==0 else "orange")
    return (res if res["ok"] else {}), dmc.Alert(res["message"],color=color), not res["ok"]

@callback(
    Output("sc-sub-msg","children"),
    Input("sc-submit-btn","n_clicks"),
    State("sc-sigma",    "value"),
    State("sc-vresult",  "data"),
    State("sc-chal-id",  "data"),
    State("auth-store",  "data"),
    prevent_initial_call=True,
)
def submit(n, yaml_text, vresult, cid, auth_data):
    if not n: return ""
    a = auth_data or {}
    if not a.get("logged_in"): return dmc.Alert("Not logged in.",color="red")
    if not vresult or not vresult.get("ok"): return dmc.Alert("Validate first.",color="orange")
    uid = a["user_id"]
    ch  = Challenge.query.get(int(cid))
    if not ch: return dmc.Alert("Challenge not found.",color="red")
    if Submission.query.filter_by(user_id=uid,challenge_id=ch.id,is_correct=True).first():
        return dmc.Alert("Already solved!",color="green")
    mid = str((vresult.get("matched_ids") or [""])[0])
    ok  = (mid == str(ch.answer_event_record_id))
    db.session.add(Submission(user_id=uid,challenge_id=ch.id,
                               submitted_sigma=yaml_text,matched_record_id=mid,is_correct=ok))
    if ok:
        u = User.query.get(uid)
        u.score += ch.points
    db.session.commit()
    if ok:
        return dmc.Alert(f"🎉 Correct! +{ch.points} points!",color="green")
    return dmc.Alert(f"✗ Wrong. Your rule matched RecordID={mid}, not the target event.",color="red")
