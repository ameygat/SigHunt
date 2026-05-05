import dash
from dash import html, dcc, Input, Output, State, callback
import dash_mantine_components as dmc
import dash_iconify
from flask_login import login_user
from utils.auth import register_user

dash.register_page(__name__, path="/register", title="Register")

def layout():
    return dmc.Center(style={"minHeight":"80vh"}, children=[
        dmc.Paper(p="xl", radius="md", withBorder=True,
                  style={"width":"100%","maxWidth":"420px"},
                  children=dmc.Stack(gap="md", children=[
                      dmc.Title("Create Account", order=2, ta="center"),
                      dmc.Text("Join SigHunt CTF", ta="center", c="dimmed", size="sm"),
                      dmc.TextInput(
                          id="reg-username", label="Username", placeholder="hacker_name",
                          leftSection=dash_iconify.DashIconify(icon="tabler:user", width=16),
                      ),
                      dmc.TextInput(
                          id="reg-email", label="Email", placeholder="you@example.com",
                          leftSection=dash_iconify.DashIconify(icon="tabler:mail", width=16),
                      ),
                      dmc.PasswordInput(
                          id="reg-password", label="Password", placeholder="Min 8 characters",
                          leftSection=dash_iconify.DashIconify(icon="tabler:lock", width=16),
                      ),
                      dmc.PasswordInput(
                          id="reg-confirm", label="Confirm Password", placeholder="Repeat password",
                          leftSection=dash_iconify.DashIconify(icon="tabler:lock-check", width=16),
                      ),
                      dmc.Alert(id="reg-error",   color="red",   style={"display":"none"}),
                      dmc.Alert(id="reg-success", color="green", style={"display":"none"}),
                      dmc.Button("Create Account", id="reg-btn", fullWidth=True, size="md"),
                      dmc.Group(justify="center", children=[
                          dmc.Text("Already have an account?", size="sm", c="dimmed"),
                          dmc.Anchor("Sign in", href="/login", size="sm"),
                      ]),
                  ])),
    ])


@callback(
    Output("url",         "pathname",  allow_duplicate=True),
    Output("auth-store",  "data",      allow_duplicate=True),
    Output("reg-error",   "children"),
    Output("reg-error",   "style"),
    Output("reg-success", "children"),
    Output("reg-success", "style"),
    Input("reg-btn",      "n_clicks"),
    State("reg-username", "value"),
    State("reg-email",    "value"),
    State("reg-password", "value"),
    State("reg-confirm",  "value"),
    prevent_initial_call=True,
)
def do_register(n, username, email, password, confirm):
    hidden = {"display":"none"}
    shown  = {"display":"block"}
    if not n:
        return dash.no_update, dash.no_update, "", hidden, "", hidden
    if not username or not email or not password or not confirm:
        return dash.no_update, dash.no_update, "All fields are required.", shown, "", hidden
    if len(username.strip()) < 3:
        return dash.no_update, dash.no_update, "Username must be at least 3 characters.", shown, "", hidden
    if len(password) < 8:
        return dash.no_update, dash.no_update, "Password must be at least 8 characters.", shown, "", hidden
    if password != confirm:
        return dash.no_update, dash.no_update, "Passwords do not match.", shown, "", hidden
    ok, result = register_user(username, email, password)
    if ok:
        user = result
        login_user(user)
        data = {"logged_in":True,"user_id":user.id,"username":user.username,
                "email":user.email,"role":user.role,"logged_in": True}
        return "/dashboard", data, "", hidden, "Account created! Redirecting...", shown
    return dash.no_update, dash.no_update, str(result), shown, "", hidden
