import dash
from dash import html, dcc, Input, Output, State, callback
import dash_mantine_components as dmc
import dash_iconify
from flask_login import login_user
from utils.auth import authenticate_user

dash.register_page(__name__, path="/login", title="Login")

def layout():
    return dmc.Center(style={"minHeight": "80vh"}, children=[
        dcc.Store(id="login-redirect-trigger", data=None),
        dmc.Paper(p="xl", radius="md", withBorder=True,
                  style={"width":"100%","maxWidth":"400px"},
                  children=dmc.Stack(gap="md", children=[
                      dmc.Title("Sign In", order=2, ta="center"),
                      dmc.Text("Welcome back to SigHunt CTF", ta="center", c="dimmed", size="sm"),
                      dmc.TextInput(
                          id="login-email", label="Email", placeholder="you@example.com",
                          leftSection=dash_iconify.DashIconify(icon="tabler:mail", width=16),
                      ),
                      dmc.PasswordInput(
                          id="login-password", label="Password", placeholder="Password",
                          leftSection=dash_iconify.DashIconify(icon="tabler:lock", width=16),
                      ),
                      dmc.Alert(id="login-error", color="red", style={"display":"none"}),
                      dmc.Button("Sign In", id="login-btn", fullWidth=True, size="md"),
                      dmc.Group(justify="center", children=[
                          dmc.Text("No account?", size="sm", c="dimmed"),
                          dmc.Anchor("Register here", href="/register", size="sm"),
                      ]),
                  ])),
    ])


@callback(
    Output("url", "href"),          # use href not pathname
    Output("auth-store", "data"),
    Output("login-error", "children"),
    Input("login-btn", "n_clicks"),
    State("login-email", "value"),
    State("login-password", "value"),
    prevent_initial_call=True
)
def do_login(n, email, password):
    if not n:
        return dash.no_update, dash.no_update, ""
    ok, result = authenticate_user(email, password)
    if not ok:
        return dash.no_update, dash.no_update, result
    user = result
    login_user(user)
    session_data = {"user_id": user.id, "username": user.username, "role": user.role,"logged_in":True}
    # Redirect based on role
    redirect = "/admin/create" if user.role == "admin" else "/dashboard"
    return redirect, session_data, ""

