import dash
from dash import html,dcc, Input, Output, State, callback, ctx
import dash_mantine_components as dmc
from utils.db import db, Challenge, Submission
dash.register_page(__name__, path="/admin/manage", title="Manage Challenges")
def layout():
    return dcc.Store(id="am-refresh", data=0),html.Div(id="am-content")

# Render callback — also listens to the store
@callback(
    Output("am-content", "children"),
    Input("url", "pathname"),
    Input("auth-store", "data"),
    Input("am-refresh", "data"),  
)
def render(path, a, _refresh):    
    a = a or {}
    if not a.get("logged_in") or a.get("role")!="admin":
        return dmc.Alert("Admin access required.",color="red")
    chals = Challenge.query.order_by(Challenge.created_at.desc()).all()
    rows = []
    for ch in chals:
        rows.append(dmc.TableTr([
            dmc.TableTd(str(ch.id)),
            dmc.TableTd(ch.title),
            dmc.TableTd(ch.category),
            dmc.TableTd(ch.difficulty),
            dmc.TableTd(str(ch.points)),
            dmc.TableTd(dmc.Badge(ch.status,color="green" if ch.status=="published" else "gray")),
            dmc.TableTd(dmc.Button("Delete",id={"type":"del-btn","index":ch.id},
                                   color="red",variant="light",size="xs")),
        ]))
    return dmc.Stack(gap="lg",children=[
        dmc.Group(justify="space-between",children=[
            dcc.Store(id="am-refresh", data=0),
            dmc.Title("Manage Challenges",order=2),
            dmc.Anchor(dmc.Button("+ New Challenge"),href="/admin/create"),
        ]),
        dmc.Alert(id="am-msg",style={"display":"none"}),
        dmc.Paper(p="md",radius="md",withBorder=True,children=dmc.Table(
            withTableBorder=True,striped=True,highlightOnHover=True,children=[
                dmc.TableThead(dmc.TableTr([dmc.TableTh(x) for x in
                    ["ID","Title","Category","Difficulty","Points","Status","Actions"]])),
                dmc.TableTbody(rows or [dmc.TableTr([dmc.TableTd("No challenges.",attributes={"colspan": "7"})])]),
            ])),
    ])


# Delete callback — only updates the store counter and alert
@callback(
    Output("am-refresh", "data"),
    Output("am-msg", "children", allow_duplicate=True),
    Output("am-msg", "color",    allow_duplicate=True),
    Output("am-msg", "style",    allow_duplicate=True),
    Input({"type": "del-btn", "index": dash.ALL}, "n_clicks"),
    State("am-refresh", "data"),
    prevent_initial_call=True,
)
def delete(clicks, refresh_count):
    if not any(clicks):
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    t = ctx.triggered_id
    if not t:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update
    ch = Challenge.query.get(t["index"])
    if ch:
        Submission.query.filter_by(challenge_id=t["index"]).delete()
        db.session.delete(ch)
        db.session.commit()
        return (refresh_count or 0) + 1, f"Challenge #{t['index']} deleted.", "orange", {"display": "block"}
    return dash.no_update, "Not found.", "red", {"display": "block"}

