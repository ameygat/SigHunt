import dash
from dash import html, Input, Output, State, callback
import dash_mantine_components as dmc
from werkzeug.security import check_password_hash, generate_password_hash
from utils.db import db, User
dash.register_page(__name__, path="/change-password", title="Change Password")
def layout():
    return dmc.Center(style={"minHeight":"80vh"},children=dmc.Paper(p="xl",radius="md",withBorder=True,
        style={"width":"100%","maxWidth":"400px"},children=dmc.Stack(gap="md",children=[
            dmc.Title("Change Password",order=3,ta="center"),
            dmc.PasswordInput(id="cp-cur", label="Current Password", placeholder="Current"),
            dmc.PasswordInput(id="cp-new", label="New Password",     placeholder="Min 8 chars"),
            dmc.PasswordInput(id="cp-con", label="Confirm",          placeholder="Repeat new"),
            dmc.Alert(id="cp-msg",style={"display":"none"}),
            dmc.Button("Update Password",id="cp-btn",fullWidth=True),
        ])))
@callback(
    Output("cp-msg","children"), Output("cp-msg","color"), Output("cp-msg","style"),
    Input("cp-btn","n_clicks"),
    State("cp-cur","value"), State("cp-new","value"), State("cp-con","value"),
    State("auth-store","data"), prevent_initial_call=True,
)
def change(n, cur, new, con, a):
    if not n: return "","green",{"display":"none"}
    a = a or {}
    if not a.get("logged_in"): return "Not logged in.","red",{"display":"block"}
    if not cur or not new or not con: return "All fields required.","red",{"display":"block"}
    if len(new)<8: return "New password >= 8 chars.","red",{"display":"block"}
    if new!=con: return "Passwords don't match.","red",{"display":"block"}
    u = User.query.get(a.get("user_id"))
    if not u: return "User not found.","red",{"display":"block"}
    if not check_password_hash(u.password_hash, cur):
        return "Current password incorrect.","red",{"display":"block"}
    u.password_hash = generate_password_hash(new)
    db.session.commit()
    return "Password updated!","green",{"display":"block"}
