import dash
from dash import html, Input, Output, State, callback
import dash_mantine_components as dmc
from utils.db import db, User
dash.register_page(__name__, path="/profile", title="Profile")
def layout():
    return html.Div(id="prof-content")
@callback(Output("prof-content","children"), Input("auth-store","data"))
def render(a):
    a = a or {}
    if not a.get("logged_in"): return dmc.Alert("Please log in.", color="red")
    u = User.query.get(a["user_id"])
    if not u: return dmc.Alert("User not found.", color="red")
    return dmc.Stack(gap="lg",children=[
        dmc.Title("My Profile",order=2),
        dmc.Paper(p="md",radius="md",withBorder=True,children=dmc.Stack(gap="md",children=[
            dmc.TextInput(id="pf-username",label="Username",value=u.username),
            dmc.TextInput(id="pf-email",   label="Email",   value=u.email, disabled=True),
            dmc.Textarea( id="pf-bio",     label="Bio",     value=u.bio or "", minRows=3),
            dmc.Alert(id="pf-msg",style={"display":"none"}),
            dmc.Button("Save Changes",id="pf-save",w=160),
        ])),
    ])
@callback(
    Output("pf-msg","children"), Output("pf-msg","color"), Output("pf-msg","style"),
    Input("pf-save","n_clicks"),
    State("pf-username","value"), State("pf-bio","value"), State("auth-store","data"),
    prevent_initial_call=True,
)
def save(n, username, bio, a):
    if not n: return "","green",{"display":"none"}
    a = a or {}
    u = User.query.get(a.get("user_id"))
    if not u: return "User not found.","red",{"display":"block"}
    if not username or len(username.strip())<3:
        return "Username >= 3 chars.","red",{"display":"block"}
    ex = User.query.filter_by(username=username.strip()).first()
    if ex and ex.id!=u.id: return "Username taken.","red",{"display":"block"}
    u.username = username.strip(); u.bio = bio or ""
    db.session.commit()
    return "Profile saved!","green",{"display":"block"}
